/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <errno.h>
#include "bio_lcl.h"
#include "internal/cryptlib.h"

static int memQ_write(BIO *h, const char *buf, int num);
static int memQ_read(BIO *h, char *buf, int size);
//static int memQ_puts(BIO *h, const char *str);
//static int memQ_gets(BIO *h, char *str, int size);
static long memQ_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int memQ_new(BIO *h);
static int memQ_free(BIO *data);
static int memQ_buf_free(BIO *data, int free_all);

static const BIO_METHOD memQ_method = {
    BIO_TYPE_MEMQ,
    "memory buffer",
    memQ_write,
    memQ_read,
//    memQ_puts,
//    memQ_gets,
    NULL,
	NULL,
    memQ_ctrl,
    memQ_new,
    memQ_free,
    NULL,
};

const BIO_METHOD *BIO_s_memQ(void)
{
    return (&memQ_method);
}

struct memQElem_st {
	char* data;
	struct memQElem_st* next;
	unsigned int length;
	unsigned int alreadyRead;
};

struct memQHead_st {
	struct memQElem_st * elem;
};

/*
 * bio->num is used to hold the value to return on 'empty', if it is 0,
 * should_retry is not set
 */

static int memQ_new(BIO *bi)
{
    struct memQHead_st *bb = OPENSSL_zalloc(sizeof(*bb));

    if (bb == NULL)
        return 0;

    bi->shutdown = 1;
    bi->init = 1;
    bi->num = -1;
    bi->ptr = (char *)bb;
    return 1;
}

static int memQ_free(BIO *a)
{
    return (memQ_buf_free(a, 1));
}

static int memQ_buf_free(BIO *a, int free_all)
{
    if (a == NULL)
        return (0);
    if (a->shutdown) {
        if ((a->init) && (a->ptr != NULL)) {
            struct memQHead_st *bb = (struct memQHead_st *)a->ptr;

            if (bb != NULL) {
				struct memQElem_st* elem = bb->elem;
				while(elem != NULL){
					struct memQElem_st* oldElem = elem;
					elem = elem->next;
					OPENSSL_free(oldElem->data);
					OPENSSL_free(oldElem);
				}
            }
        }
    }
    return (1);
}

static int memQ_read(BIO *b, char *out, int outl)
{
    int ret = -1;

	if(b != NULL){
		struct memQHead_st* head = (struct memQHead_st*) b->ptr;

		if(head != NULL){
			struct memQElem_st* elem = head->elem;

			if(elem != NULL){
				unsigned int dataLen = elem->length - elem->alreadyRead;

				unsigned int cpyLen = 0;
				if(dataLen < ((unsigned int)outl)){
					cpyLen = dataLen;
				} else {
					cpyLen = outl;
				}

				memcpy(out, elem->data + elem->alreadyRead, cpyLen);

				elem->alreadyRead += cpyLen;

				if(elem->alreadyRead >= elem->length){
					struct memQElem_st* old = elem;
					head->elem = elem->next;
					OPENSSL_free(old->data);
					OPENSSL_free(old);
				}

				return cpyLen;
			}
		}
	}

    return (ret);
}

static int memQ_write(BIO *b, const char *in, int inl)
{
	if(b != NULL){
		struct memQHead_st* head = (struct memQHead_st*) b->ptr;

		if(head != NULL){

			struct memQElem_st* newElem =
				(struct memQElem_st*) OPENSSL_zalloc(sizeof(struct memQElem_st));
			newElem->data = OPENSSL_zalloc(inl);
			newElem->length = inl;
			newElem->next = NULL;
			newElem->alreadyRead = 0;

			memcpy(newElem->data, in, inl);


			if(head->elem != NULL){
				struct memQElem_st* cur = head->elem;
				while(cur->next != NULL){
					cur = cur->next;
				}
				cur->next = newElem;
			} else {
				head->elem = newElem;
			}

			return inl;
		}
	}

	return -1;
}

static long memQ_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = -1;

	struct memQHead_st* head;

	if(b != NULL){
		head = (struct memQHead_st*) b->ptr;
	} else {
		return ret;
	}

    switch (cmd) {
    case BIO_CTRL_EOF:
		if(head != NULL){
			if(head->elem == NULL){
				ret = 1;
			} else {
				ret = 0;
			}
		}
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = (long)b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_WPENDING:
        ret = 0L;
        break;
    case BIO_CTRL_PENDING:
		ret = 0;
		if(head != NULL){
			struct memQElem_st* elem = head->elem;
			if(elem != NULL){
				ret = elem->length - elem->alreadyRead;
			}
		}
        break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
        ret = 1;
        break;
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
    default:
        ret = 0;
        break;
    }
    return (ret);
}

#if 0
static int mem_gets(BIO *bp, char *buf, int size)
{
    int i, j;
    int ret = -1;
    char *p;
    BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)bp->ptr;
    BUF_MEM *bm = bbm->readp;

    BIO_clear_retry_flags(bp);
    j = bm->length;
    if ((size - 1) < j)
        j = size - 1;
    if (j <= 0) {
        *buf = '\0';
        return 0;
    }
    p = bm->data;
    for (i = 0; i < j; i++) {
        if (p[i] == '\n') {
            i++;
            break;
        }
    }

    /*
     * i is now the max num of bytes to copy, either j or up to
     * and including the first newline
     */

    i = mem_read(bp, buf, i);
    if (i > 0)
        buf[i] = '\0';
    ret = i;
    return (ret);
}

static int mem_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = mem_write(bp, str, n);
    /* memory semantics is that it will always work */
    return (ret);
}
#endif
