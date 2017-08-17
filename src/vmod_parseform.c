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


VCL_STRING search_multipart(VRT_CTX,VCL_STRING key, VCL_STRING glue, struct vsb *vsb){
	char *st,*nxt;
	char *lim,*name,*namelim;

	st = nxt = VSB_data(vsb);
	const char *tmp= VRT_GetHdr(ctx, &VGC_HDR_REQ_content_2d_type);
	char *raw_boundary = strstr(tmp,"; boundary=");
	if(!raw_boundary) return "";
	raw_boundary+=11;
	

	char *boundary    = WS_Alloc(ctx->ws, strlen(raw_boundary)+3);
	boundary[0]  = '-';
	boundary[1]  = '-';
	memcpy(boundary+2,raw_boundary,strlen(raw_boundary));
	boundary[strlen(raw_boundary)+2] = 0;
	
	ssize_t boundary_len = strlen(boundary);
	st = strstr(nxt, boundary) + boundary_len;
	if(!st) return"";
	ssize_t keylen   = strlen(key);
	ssize_t bodylen,glen;
	glen = strlen(glue);

	unsigned u;
	u = WS_Reserve(ctx->ws, 0);
	char *rpp,*rp;
	rpp = rp = ctx->ws->f;

	
	while(1){
		//次のboundary
		nxt = strstr(st, boundary);
		if(!nxt) break;
		
		if(st[0]!='\r' || st[1] != '\n') break;
		st+=2;
		lim = strstr(st,"\r\n\r\n");
		name= strstr(st," name=\"");
		if(name ==NULL || lim < name) break;
		name+=7;
		lim +=4;
		namelim= strstr(name,"\"");
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

	if(rp == rpp) return "";
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
	ssize_t len,orglen,glen;
	glen = strlen(glue);
	len=orglen= VSB_len(vsb);
	ssize_t keylen   = strlen(key);
	unsigned u;
	u = WS_Reserve(ctx->ws, 0);
	char *rpp,*rp;
	rpp = rp = ctx->ws->f;
	
	
	while(1){
		eq = memchr(p,'=',len);
		if(eq == NULL) break;
		p  = eq +1;
		len = orglen-(p -porg);
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
			amp = memchr(p,'&',len);
			if(amp==NULL){
				//last
				bodylen =len;
				p +=len;
				len = orglen-(p -porg);
			}else{
				bodylen =amp-eq-1;
				p = amp +1;
				len = orglen-(p -porg);
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
	if(rp == rpp) return "";
	rp++;
	u--;
	rp[0] = 0;
	WS_Release(ctx->ws, rp - rpp);
	return rpp;
}


int __match_proto__(vmod_event_f)
event_function(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{


	switch (e) {
	case VCL_EVENT_LOAD:
		break;
	case VCL_EVENT_WARM:
		break;
	case VCL_EVENT_COLD:
		break;
	case VCL_EVENT_DISCARD:
		return (0);
		break;
	default:
		return (0);
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
	}
	return "";
}

