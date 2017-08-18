#define _GNU_SOURCE

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

/* need vcl.h before vrt.h for vmod_evet_f typedef */
#include "vcl.h"
#include "vrt.h"
#include "cache/cache.h"

#include "vtim.h"
#include "vcc_parseform_if.h"

#include "vre.h"

#include <syslog.h>


struct vmod_priv_parseform{
	unsigned	magic;
#define VMOD_PRIV_PARSEFORM_MAGIC	0xf8afce84
	struct vsb	*vsb;
};
static const struct gethdr_s VGC_HDR_REQ_content_2d_type =
    { HDR_REQ, "\015content-type:"};



static int __match_proto__(objiterate_f)
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
VCL_STRING search_plain(VRT_CTX,VCL_STRING key, VCL_STRING glue, struct vsb *vsb){

	char *st,*nxt, *eq,*lim,*ta,*tl,*nxeq;
	st =nxt = VSB_data(vsb);
	char *last = st+ VSB_len(vsb);
	ssize_t glen,keylen,bodylen;
	glen = strlen(glue);
	keylen = strlen(key);
	eq = memchr(st,'=',last-st);
	
	if(!eq) return "";
	unsigned u;
	u = WS_Reserve(ctx->ws, 0);
	char *rpp,*rp;
	rpp = rp = ctx->ws->f;
	
	while(1){
		if(!eq)break;
		
		nxeq = memchr(eq+1,'=',last-eq-1);
		if(!nxeq){
			lim = last;
		}else{
			tl = ta = eq;
			
			while(1){
				ta = memmem(ta,last-ta,"\r\n",2);
				if(!ta || nxeq < ta){
					lim = tl;
					break;
				}
				tl = ta;
				ta+=2;
			}
		}
		if(keylen == eq -st   && !memcmp(st, key,keylen)){
			if(rp > rpp){
				memcpy(rp,glue,glen);
				rp+=glen;
				u-=glen;
			}
			bodylen = lim-eq-1;
			if(u < bodylen + glen + 1){
				WS_Release(ctx->ws, 0);
				WS_MarkOverflow(ctx->ws);
				return "";
			}
			
			memcpy(rp,eq+1, bodylen);
			rp+=bodylen;
			u-=bodylen;

		}
		st = lim+2;
		eq = nxeq;
		if(st > last)break;
	}
	
	if(rp == rpp){
		WS_Release(ctx->ws, 0);
		return "";
	}
	rp++;
	u--;
	rp[0] = 0;
	WS_Release(ctx->ws, rp - rpp);
	return rpp;
}
VCL_STRING search_multipart(VRT_CTX,VCL_STRING key, VCL_STRING glue, struct vsb *vsb){
	char *st,*nxt;
	char *lim,*name,*namelim;

	st = nxt = VSB_data(vsb);
	char *last = st + VSB_len(vsb);
	const char *tmp= VRT_GetHdr(ctx, &VGC_HDR_REQ_content_2d_type);
	char *raw_boundary = memmem(tmp,last -tmp,"; boundary=",11);
	if(!raw_boundary) return "";
	raw_boundary+=11;
	

	char *boundary    = WS_Alloc(ctx->ws, strlen(raw_boundary)+3);
	boundary[0]  = '-';
	boundary[1]  = '-';
	memcpy(boundary+2,raw_boundary,strlen(raw_boundary));
	boundary[strlen(raw_boundary)+2] = 0;
	
	ssize_t boundary_len = strlen(boundary);
	st = memmem(nxt,last-nxt, boundary,boundary_len) + boundary_len;
	if(!st) return"";
	ssize_t keylen   = strlen(key);
	ssize_t bodylen,glen;
	glen = strlen(glue);

	unsigned u;
	u = WS_Reserve(ctx->ws, 0);
	char *rpp,*rp;
	rpp = rp = ctx->ws->f;

	
	while(1){
		nxt = memmem(st,last-st, boundary,boundary_len);
		if(!nxt) break;
		
		if(st[0]!='\r' || st[1] != '\n') break;
		st+=2;
		lim = memmem(st,last-st,"\r\n\r\n",4);
		name= memmem(st,last-st," name=\"",7);
		if(name ==NULL || lim < name) break;
		name+=7;
		lim +=4;
		namelim= memchr(name,'"',last -name);
		if(namelim ==NULL || lim < namelim) break;
		if(keylen == namelim - name  && !memcmp(name, key,keylen)){
			if(rp > rpp){
				memcpy(rp,glue,glen);
				rp+=glen;
				u-=glen;
			}
			
			bodylen = nxt -lim -2;
			if(u < bodylen + glen + 1){
				WS_Release(ctx->ws, 0);
				WS_MarkOverflow(ctx->ws);
				return "";
			}
			
			memcpy(rp,lim, bodylen);
			rp+=bodylen;
			u-=bodylen;
		}
		st = nxt + boundary_len;
	}

	if(rp == rpp){
		WS_Release(ctx->ws, 0);
		return "";
	}
	rp++;
	u--;
	rp[0] = 0;
	WS_Release(ctx->ws, rp - rpp);
	return rpp;

}
VCL_STRING search_urlencoded(VRT_CTX,VCL_STRING key, VCL_STRING glue, struct vsb *vsb){
	char *pkey;
	char *p,*porg;
	p = porg= VSB_data(vsb);
	char *eq,*amp;
	ssize_t bodylen;
	ssize_t glen;
	glen = strlen(glue);
	char *last = porg + VSB_len(vsb);
	ssize_t keylen   = strlen(key);
	unsigned u;
	u = WS_Reserve(ctx->ws, 0);
	char *rpp,*rp;
	rpp = rp = ctx->ws->f;
	
	
	while(1){
		eq = memchr(p,'=',last -p);
		if(eq == NULL) break;
		p  = eq +1;
		if(eq - keylen < porg){
			continue;
		}
		pkey = eq -keylen;
		if(!memcmp(pkey, key,keylen)){
			if(rp > rpp){
				memcpy(rp,glue,glen);
				rp+=glen;
				u-=glen;
			}
			amp = memchr(p,'&',last -p);
			if(amp==NULL){
				//last
				bodylen =last -p;
				p +=bodylen;
			}else{
				bodylen =amp-eq-1;
				p = amp +1;
			}
			if(u < bodylen + glen + 1){
				WS_Release(ctx->ws, 0);
				WS_MarkOverflow(ctx->ws);
				return "";
			}
			
			memcpy(rp,eq +1, bodylen);
			rp+=bodylen;
			u-=bodylen;
			
		}
	}
	if(rp == rpp){
		WS_Release(ctx->ws, 0);
		return "";
	}
	rp++;
	u--;
	rp[0] = 0;
	WS_Release(ctx->ws, rp - rpp);
	return rpp;
}


int __match_proto__(vmod_event_f)
event_function(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
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

VCL_STRING 
vmod_get(VRT_CTX, struct vmod_priv *priv, VCL_STRING key, VCL_STRING glue)
{
	if (ctx->req->req_body_status != REQ_BODY_CACHED) {
		VSLb(ctx->vsl, SLT_VCL_Error,
		   "Unbuffered req.body");
		return "";
	}
	if (ctx->method != VCL_MET_RECV) {
		VSLb(ctx->vsl, SLT_VCL_Error,
		    "len_req_body can only be used in vcl_recv{}");
		return "";
	}
	
	if (priv->priv == NULL) getbody(ctx, &priv);
	
	const char *ctype= VRT_GetHdr(ctx, &VGC_HDR_REQ_content_2d_type);
	
	if(!strcmp(ctype, "application/x-www-form-urlencoded")){
		return search_urlencoded(ctx, key, glue, ((struct vmod_priv_parseform *)priv->priv)->vsb);
	}else if(strlen(ctype) > 19 && !memcmp(ctype, "multipart/form-data",19)){
		return search_multipart (ctx, key, glue, ((struct vmod_priv_parseform *)priv->priv)->vsb);
	}else if(!strcmp(ctype, "text/plain")){
		return search_plain     (ctx, key, glue, ((struct vmod_priv_parseform *)priv->priv)->vsb);
	}
	return "";
}

