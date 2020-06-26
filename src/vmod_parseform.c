#define _GNU_SOURCE

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

/* need vcl.h before vrt.h for vmod_evet_f typedef */
#include <cache/cache_varnishd.h>
#include "vcl.h"
#ifndef VRT_H_INCLUDED
	#include "vrt.h"
#endif
#ifndef VDEF_H_INCLUDED
	#include <vdef.h>
#endif
#include "vre.h"

#include "vsb.h"
#include "vtim.h"
#include "vcc_parseform_if.h"
struct vmod_priv_parseform{
	unsigned	magic;
#define VMOD_PRIV_PARSEFORM_MAGIC	0xf8afce84
	struct vsb	*vsb;
};

static const struct gethdr_s vmod_priv_parseform_contenttype =
    { HDR_REQ, "\015content-type:"};

static struct surlenc {
	char hex2bin[256];
	char bin2hex[16];
	char skipchr[256];
} urlenc;

static void initUrlcode(){
	const char *p;
	char *hex     = "0123456789abcdefABCDEF";
	char *bin2hex = "0123456789ABCDEF";
	char *skip    = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int i;
	
	memset(urlenc.hex2bin, -1, 256);
	memset(urlenc.skipchr, 0, 256);

	for (i=0; i< 16; i++)
		urlenc.bin2hex[i] = bin2hex[i];

	for (p = hex; *p; p++){
		if(p[0] >= '0' && p[0] <= '9'){
			urlenc.hex2bin[(int)*p] = p[0] - '0';
		}else if(p[0] >= 'A' && p[0] <= 'F'){
			urlenc.hex2bin[(int)*p] = p[0] - 'A' +10;
		}else{
			urlenc.hex2bin[(int)*p] = p[0] - 'a' +10;
		}
	}
	for (p = skip; *p; p++)
		urlenc.skipchr[(int)*p] = 1;

}


VCL_STRING urlencode(VRT_CTX, VCL_BLOB blob){
	unsigned   u;
	char       *rpp, *rp;
	const char *p;
	u = WS_Reserve(ctx->ws, 0);
	rpp = rp = ctx->ws->f;
	

	for (p = blob->priv; p < (char*)(blob->priv +blob->len); p++){
		if(u < 4){
			WS_Release(ctx->ws, 0);
			WS_MarkOverflow(ctx->ws);
			return "";
		}
		if(urlenc.skipchr[(int)p[0]]){
			rp[0] = p[0];
			rp++;
			u--;
		}else{
			rp[0] = '%';
			rp[1] = urlenc.bin2hex[p[0] >>4];
			rp[2] = urlenc.bin2hex[p[0] & 0x0f];
			rp+=3;
			u -=3;
		}
	}
	if(rp == rpp){
		WS_Release(ctx->ws, 0);
		return "";
	}
	rp[0] = 0;
	rp++;
	u--;

	WS_Release(ctx->ws, rp - rpp);
	return rpp;
}

VCL_BLOB urldecode(VRT_CTX, VCL_STRING txt){
	const char *last, *per, *nxtper;
	unsigned   u;
	char       *rpp, *rp, *plus;
	struct vmod_priv *p;
	p = (void*)WS_Alloc(ctx->ws, sizeof *p);
	AN(p);
	memset(p, 0, sizeof *p);
	
	u = WS_Reserve(ctx->ws, 0);
	rpp = rp = ctx->ws->f;
	last = txt + strlen(txt);
	ssize_t bodylen;
	per = txt;
	while(1){
		nxtper = strchr(per, '%');
		if(!nxtper) break;
		if(nxtper + 2 > last) break;
		if(u < 4){
			WS_Release(ctx->ws, 0);
			WS_MarkOverflow(ctx->ws);
			return p;
		}
		if(nxtper != per){
			bodylen = nxtper - per;
			if(u < bodylen +1){
				WS_Release(ctx->ws, 0);
				WS_MarkOverflow(ctx->ws);
				return p;
			}
			memcpy(rp, per, bodylen);
			rp +=bodylen;
			u  -=bodylen;
		}
		if(urlenc.hex2bin[(int)nxtper[1]] >= 0 && urlenc.hex2bin[(int)nxtper[2]] >= 0){
			rp[0] = (urlenc.hex2bin[(int)nxtper[1]] << 4) | urlenc.hex2bin[(int)nxtper[2]];
			rp ++;
			u  --;
			nxtper+=3;
		}else{
			rp[0] = '%';
			rp ++;
			u  --;
			nxtper++;
		}
		per = nxtper;
	}

	if(last > per){
		bodylen = last -per;
		memcpy(rp, per, bodylen);
		rp +=bodylen;
		u  -=bodylen;
	}

	rp[0] = 0;
	rp++;
	u--;
	p->len = rp -rpp -1;

	plus = rpp;
	while(1){
		plus = strchr(plus, '+');
		if(!plus) break;
		plus[0] = ' ';
	}
	
	
	WS_Release(ctx->ws, rp - rpp);
	p->priv = rpp;
	return p;
}


static int
IterCopyReqBody(void *priv, int flush, const void *ptr, ssize_t len)
{
	struct vsb *iter_vsb = priv;

	return (VSB_bcat(iter_vsb, ptr, len));
}

void
VRB_Blob(VRT_CTX, struct vsb *vsb)
{
	int l;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(ctx->req, REQ_MAGIC);

	l = VRB_Iterate(ctx->req, IterCopyReqBody, (void*)vsb);
	VSB_finish(vsb);
	if (l < 0) {
		VSB_delete(vsb);
		VSLb(ctx->vsl, SLT_VCL_Error,
		    "Iteration on req.body didn't succeed.");
		return;
	}
}

VCL_BLOB search_plain(VRT_CTX, VCL_STRING key, VCL_STRING glue, struct vsb *vsb){

	char    *st, *nxt, *eq, *lim, *nxeq, *last;
	ssize_t glen,keylen,bodylen;

	unsigned u;
	char     *rpp, *rp;
	struct vmod_priv *bp;
	bp = (void*)WS_Alloc(ctx->ws, sizeof *bp);
	AN(bp);
	memset(bp, 0, sizeof *bp);
	bp->len = 0;
	st   = nxt = VSB_data(vsb);
	last = st+ VSB_len(vsb);
	eq = memchr(st, '=', last -st);


	if(!eq) return bp;
	glen   = strlen(glue);
	keylen = strlen(key);
	
	u = WS_Reserve(ctx->ws, 0);
	rpp = rp = ctx->ws->f;
	
	while(1){
		if(!eq)break;
		
		nxeq = memchr(eq +1, '=', last -eq -1);
		if(!nxeq){
			lim = last;
		}else{
			lim = memrchr(eq, '\r', nxeq- eq);
			if(lim[1] != '\n') break;
		}
		if(keylen == eq -st && !strncasecmp(st, key, keylen)){
			bodylen = lim -eq -1;
			if(u < bodylen + glen +1){
				WS_Release(ctx->ws, 0);
				WS_MarkOverflow(ctx->ws);
				return bp;
			}
			
			if(rp > rpp && bodylen){
				memcpy(rp, glue, glen);
				rp +=glen;
				u  -=glen;
			}
			memcpy(rp, eq +1, bodylen);
			rp +=bodylen;
			u  -=bodylen;

		}
		st = lim +2;
		eq = nxeq;
		if(st > last)break;
	}
	
	if(rp == rpp){
		WS_Release(ctx->ws, 0);
		return bp;
	}
	rp[0] = 0;
	rp++;
	u--;
	bp->len  = rp -rpp -1;
	bp->priv = rpp;
	WS_Release(ctx->ws, rp - rpp);
	return bp;
}

VCL_BLOB search_multipart(VRT_CTX,VCL_STRING key, VCL_STRING glue, struct vsb *vsb){
	char       *st, *nxt, *last;
	char       *lim, *name, *namelim;
	char       *raw_boundary, *boundary;
	const char *tmp;
	ssize_t    boundary_len, keylen, bodylen, glen;
	
	unsigned u;
	char     *rpp, *rp;
	struct vmod_priv *bp;
	bp = (void*)WS_Alloc(ctx->ws, sizeof *bp);
	AN(bp);
	memset(bp, 0, sizeof *bp);
	bp->len = 0;
	st   = nxt = VSB_data(vsb);
	last = st +VSB_len(vsb);


	tmp  = VRT_GetHdr(ctx, &vmod_priv_parseform_contenttype);
	raw_boundary = memmem(tmp, last - tmp, "; boundary=", 11);
	if(!raw_boundary) return bp;
	raw_boundary += 11;
	

	boundary     = WS_Alloc(ctx->ws, strlen(raw_boundary) +3);
	boundary[0]  = '-';
	boundary[1]  = '-';
	memcpy(boundary + 2, raw_boundary, strlen(raw_boundary));
	boundary[strlen(raw_boundary) +2] = 0;
	
	boundary_len = strlen(boundary);
	st = memmem(nxt, last-nxt, boundary, boundary_len) + boundary_len;
	if(!st) return bp;
	keylen = strlen(key);
	glen   = strlen(glue);

	u   = WS_Reserve(ctx->ws, 0);
	rpp = rp = ctx->ws->f;

	while(1){
		nxt = memmem(st, last - st, boundary, boundary_len);
		if(!nxt) break;
		
		if(st[0]!='\r' || st[1] != '\n') break;
		st +=2;
		lim  = memmem(st, last-st, "\r\n\r\n", 4);
		name = memmem(st, last-st, " name=\"", 7);
		if(name == NULL || lim == NULL || lim < name) break;
		name +=7;
		lim  +=4;
		namelim = memchr(name, '"', last - name);
		if(namelim == NULL || lim < namelim) break;
		if(keylen == namelim - name  && !strncasecmp(name, key, keylen)){
			
			bodylen = nxt -lim -2;
			if(u < bodylen +glen +1){
				WS_Release(ctx->ws, 0);
				WS_MarkOverflow(ctx->ws);
				return bp;
			}
			
			if(rp > rpp && bodylen){
				memcpy(rp, glue, glen);
				rp +=glen;
				u  -=glen;
			}
			memcpy(rp, lim, bodylen);
			rp +=bodylen;
			u  -=bodylen;
		}
		st = nxt +boundary_len;
	}

	if(rp == rpp){
		WS_Release(ctx->ws, 0);
		return bp;
	}
	rp[0] = 0;
	rp++;
	u--;
	bp->len  = rp -rpp -1;
	bp->priv = rpp;
	WS_Release(ctx->ws, rp - rpp);
	return bp;

}

VCL_BLOB search_urlencoded(VRT_CTX,VCL_STRING key, VCL_STRING glue, struct vsb *vsb){
	char    *pkey;
	char    *p, *porg, *last;
	char    *eq, *amp;
	ssize_t bodylen, keylen;
	ssize_t glen;

	unsigned u;
	char *rpp, *rp;
	struct vmod_priv *bp;
	bp = (void*)WS_Alloc(ctx->ws, sizeof *bp);
	AN(bp);
	memset(bp, 0, sizeof *bp);
	bp->len = 0;

	p      = porg= VSB_data(vsb);
	glen   = strlen(glue);
	last   = porg + VSB_len(vsb);
	keylen = strlen(key);
	
	u      = WS_Reserve(ctx->ws, 0);
	rpp    = rp = ctx->ws->f;
	
	
	while(1){
		eq = memchr(p, '=', last -p);
		if(eq == NULL) break;
		p  = eq + 1;
		pkey = eq - keylen;
		if(pkey < porg){
			continue;
		}
		
		if((pkey == porg || (pkey -1)[0] == '&') && !strncasecmp(pkey, key, keylen)){
			//key match
			amp = memchr(p, '&', last -p);
			if(amp == NULL){
				//last
				bodylen = last - p;
			}else{
				bodylen = amp  - p;
			}
			if(u < bodylen + glen +1){
				WS_Release(ctx->ws, 0);
				WS_MarkOverflow(ctx->ws);
				return bp;
			}
			if(rp > rpp && bodylen){
				memcpy(rp, glue, glen);
				rp += glen;
				u  -= glen;
			}
			
			memcpy(rp,p, bodylen);
			rp += bodylen;
			u  -= bodylen;
			p  += bodylen;
			
		}
	}
	
	if(rp == rpp){
		WS_Release(ctx->ws, 0);
		return bp;
	}
	rp[0] = 0;
	rp++;
	u--;
	bp->len  = rp -rpp -1;
	bp->priv = rpp;
	WS_Release(ctx->ws, rp - rpp);
	return bp;
}


int
event_function(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
	switch (e) {
	case VCL_EVENT_LOAD:
		initUrlcode();
		break;
	default:
		break;
	}

	return (0);
}

static void vmod_free(void *priv){
	struct vmod_priv_parseform *tmp = priv;
	VSB_delete(tmp->vsb);
	FREE_OBJ(tmp);
}

void getbody(VRT_CTX, struct vmod_priv **priv){
	struct vmod_priv_parseform *tmp;
	ALLOC_OBJ(tmp,VMOD_PRIV_PARSEFORM_MAGIC);
	(*priv)->priv = tmp;
	tmp->vsb=VSB_new_auto();
	(*priv)->free = vmod_free;
	VRB_Blob(ctx, tmp->vsb);
}


VCL_BLOB
vmod_get_blob(VRT_CTX, struct vmod_priv *priv, VCL_STRING key, VCL_STRING glue, VCL_BOOL decode)
{
	

	if (ctx->req->req_body_status != REQ_BODY_CACHED) {
		VSLb(ctx->vsl, SLT_VCL_Error,
		   "Unbuffered req.body");
		struct vmod_priv *nr = NULL;
		nr = (void*)WS_Alloc(ctx->ws, sizeof *nr);
		AN(nr);
		memset(nr, 0, sizeof *nr);
		return nr;
	}
	if (ctx->method != VCL_MET_RECV) {
		VSLb(ctx->vsl, SLT_VCL_Error,
		    "len_req_body can only be used in vcl_recv{}");
		struct vmod_priv *nr = NULL;
		nr = (void*)WS_Alloc(ctx->ws, sizeof *nr);
		AN(nr);
		memset(nr, 0, sizeof *nr);
		return nr;
	}

	const struct vmod_priv *ret = NULL;

	if (priv->priv == NULL) getbody(ctx, &priv);

	const char *ctype= VRT_GetHdr(ctx, &vmod_priv_parseform_contenttype);

	if(!strncasecmp(ctype, "application/x-www-form-urlencoded", 33)){
		ret = search_urlencoded(ctx, key, glue, ((struct vmod_priv_parseform *)priv->priv)->vsb);
		if(ret->len > 0 && decode){
			ret = urldecode(ctx, ret->priv);
		}
	}else if(strlen(ctype) > 19 && !strncasecmp(ctype, "multipart/form-data", 19)){
		ret = search_multipart (ctx, key, glue, ((struct vmod_priv_parseform *)priv->priv)->vsb);
	}else if(!strncasecmp(ctype, "text/plain", 10)){
		ret = search_plain     (ctx, key, glue, ((struct vmod_priv_parseform *)priv->priv)->vsb);
	}else{
		struct vmod_priv *nr = NULL;
		nr = (void*)WS_Alloc(ctx->ws, sizeof *nr);
		AN(nr);
		memset(nr, 0, sizeof *nr);
		return nr;
	}
	return ret;
}
VCL_STRING
vmod_get(VRT_CTX, struct vmod_priv *priv, VCL_STRING key, VCL_STRING glue, VCL_ENUM encode)
{
	int enc = 0;
	if(!strcmp(encode, "urlencode")){
		enc = 1;
	}
	const struct vmod_priv *ret = vmod_get_blob(ctx, priv, key, glue, enc);
	const char *rc = NULL;

	if(ret && ret->len > 0){
		if(enc){
			rc = urlencode(ctx, ret);
		}else{
			rc = ret->priv;
		}
		return rc;
	}
	return "";
}

VCL_INT
vmod_len(VRT_CTX, struct vmod_priv *priv, VCL_STRING key, VCL_STRING glue)
{
	const struct vmod_priv *ret = vmod_get_blob(ctx, priv, key, glue, 0);
	return ret->len;
}

VCL_STRING
vmod_urldecode(VRT_CTX, VCL_STRING txt){
	const struct vmod_priv *p;
	p = urldecode(ctx,txt);
	return p->priv;
}

VCL_STRING
vmod_urlencode(VRT_CTX, VCL_STRING txt){
	struct vmod_priv p;
	p.priv = (void*)txt;
	p.len  = strlen(txt);
	return urlencode(ctx, &p);
}

VCL_BLOB
vmod_urldecode_blob(VRT_CTX, VCL_STRING txt){
	return urldecode(ctx,txt);
}

VCL_STRING
vmod_urlencode_blob(VRT_CTX, VCL_BLOB blob){
	return urlencode(ctx, blob);
}
