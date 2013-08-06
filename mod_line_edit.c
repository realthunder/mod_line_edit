/********************************************************************
  Copyright (c) 2005-6, WebThing Ltd
  Author: Nick Kew <nick@webthing.com>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*********************************************************************/


#define LINE_EDIT_VERSION "1.0.0"

#include <ctype.h>

#include <pcre.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <util_filter.h>

#include <apr_strmatch.h>
#include <apr_strings.h>

#ifdef AP_REG_ICASE
#define APACHE21
#else
#define APACHE20
#endif

#ifdef APACHE20
#define ap_regex_t regex_t
#define ap_regmatch_t regmatch_t
#define AP_REG_EXTENDED REG_EXTENDED
#define AP_REG_ICASE REG_ICASE
#define AP_REG_NOSUB REG_NOSUB
#define AP_REG_NEWLINE REG_NEWLINE

/* we don't have protocol handling in 2.0 */
#define ap_register_output_filter_protocol(a,b,c,d,e) \
	ap_register_output_filter(a,b,c,d)
#endif

#define M_REGEX		0x01
#define M_NOCASE	0x08
#define M_NEWLINE	0x10
#define M_ENV		0x20
#define M_ENV_FROM	0x40
#define M_START	        0x80
#define M_END	        0x100
#define M_EXCLUSIVE     0x200
#define M_END_EX        0x300

typedef struct {
  const char* env;
  const char* val;
  int rel;
} rewritecond;
typedef struct {
  union {
    const apr_strmatch_pattern* s;
    const ap_regex_t* r ;
  } from ;
  const char *from_save;
  const char* to ;
  unsigned int flags ;
  unsigned int length ;
  unsigned int to_length ;
  rewritecond *cond;
} rewriterule ;

typedef struct {
  enum {
	LINEEND_UNSET,
	LINEEND_ANY,
	LINEEND_UNIX,
	LINEEND_MAC,
	LINEEND_DOS,
	LINEEND_CUSTOM,
	LINEEND_NONE
  } lineend ;
  apr_array_header_t* rewriterules ;
  int lechar;
  int verbose;
} line_edit_cfg ;

module AP_MODULE_DECLARE_DATA line_edit_module ;

static const char* const line_edit_filter_name = "line-editor" ;

typedef struct {
  apr_bucket_brigade* bbsave ;
  apr_array_header_t* rewriterules ; /* make a copy if per-request
					interpolation is wanted */
  rewriterule *rulestart;
  rewriterule *ruleend;
  request_rec *pending;
  int offs;
} line_edit_ctx ;

static const char* interpolate_env(request_rec *r, const char *str) {
  /* Interpolate an env str in a configuration string
   * Syntax ${var} --> value_of(var)
   * Method: replace one var, and recurse on remainder of string
   * Nothing clever here, and crap like nested vars may do silly things
   * but we'll at least avoid sending the unwary into a loop
   */
  const char *start;
  const char *end;
  const char *var;
  const char *val;
  const char *firstpart;

  start = ap_strstr(str, "${");
  if (start == NULL) {
    return str;
  }
  end = ap_strchr(start+2, '}');
  if (end == NULL) {
    return str;
  }
  /* OK, this is syntax we want to interpolate.  Is there such a var ? */
  var = apr_pstrndup(r->pool, start+2, end-(start+2));
  val = apr_table_get(r->subprocess_env, var);
  firstpart = apr_pstrndup(r->pool, str, (start-str));

  if (val == NULL) {
    return apr_pstrcat(r->pool, firstpart, interpolate_env(r, end+1), NULL);
  } else {
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG,0,r,"Interpolating %s  =>  %s", var, val) ;
    return apr_pstrcat(r->pool, firstpart, val,
	interpolate_env(r, end+1), NULL);
  }
}
static int compile_rule(apr_pool_t *pool, rewriterule *rule) {
    int lflags = 0 ;
    if ( rule->flags & M_REGEX ) {
        if ( rule->flags & M_NOCASE ) {
            lflags |= AP_REG_ICASE;
        }
        if ( rule->flags & M_NEWLINE ) {
            lflags |= AP_REG_NEWLINE;
        }
        if((rule->from.r = ap_pregcomp(pool, rule->from_save, lflags))==NULL){
            return 1;
        }
    } else {
        lflags = (rule->flags & M_NOCASE) ? 0 : 1 ;
        rule->length = strlen(rule->from_save) ;
        rule->to_length = strlen(rule->to) ;
        rule->from.s = apr_strmatch_precompile(pool, rule->from_save, lflags) ;
    }
    return 0;
}
int check_save(ap_filter_t* f, apr_bucket **pb, 
        const char **pbuf, apr_size_t *pbytes) {
    line_edit_ctx *ctx = f->ctx;
    int rv;
    apr_bucket *b1,*b=*pb;
    if (APR_BRIGADE_EMPTY(ctx->bbsave) || ctx->offs<0) return 0;
    b1 = APR_BUCKET_NEXT(b) ;
    APR_BUCKET_REMOVE(b);
    APR_BRIGADE_INSERT_TAIL(ctx->bbsave, b) ;
    rv = apr_brigade_pflatten(ctx->bbsave, (char**)pbuf, pbytes, f->r->pool) ;
    *pb = b = apr_bucket_pool_create(*pbuf, *pbytes, f->r->pool,
            f->r->connection->bucket_alloc) ;
    apr_brigade_cleanup(ctx->bbsave) ;
    APR_BUCKET_INSERT_BEFORE(b1,b);
    return rv != APR_SUCCESS || *pbytes == 0;
}
static apr_status_t line_edit_filter(ap_filter_t* f, apr_bucket_brigade* bb) {
  int i, j, rc;
  unsigned int match ;
  unsigned int nmatch = 10 ;
  ap_regmatch_t pmatch[15] ;
  const char* bufp;
  const char* subs ;
  apr_size_t bytes ;
  apr_size_t fbytes ;
  apr_size_t offs ;
  const char* buf ;
  const char* le = NULL ;
  const char* le_n ;
  const char* le_r ;
  char* fbuf ;
  apr_bucket* b = APR_BRIGADE_FIRST(bb) ;
  apr_bucket* b1 ;
  int found = 0 ;
  apr_status_t rv ;

  apr_bucket_brigade* bbline ;
  line_edit_cfg* cfg
	= ap_get_module_config(f->r->per_dir_config, &line_edit_module) ;
  rewriterule* rules = (rewriterule*) cfg->rewriterules->elts ;
  rewriterule* newrule;

  line_edit_ctx* ctx = f->ctx ;
  if (ctx == NULL) {

    /* check env to see if we're wanted, to give basic control with 2.0 */
    buf = apr_table_get(f->r->subprocess_env, "LineEdit");
    if (buf && f->r->content_type) {
      char* lcbuf = apr_pstrdup(f->r->pool, buf) ;
      char* lctype = apr_pstrdup(f->r->pool, f->r->content_type) ;
      char* c ;

      for (c = lcbuf; *c; ++c)
	if (isupper(*c))
	  *c = tolower(*c) ;

      for (c = lctype; *c; ++c)
	if (isupper(*c))
	  *c = tolower(*c) ;
	else if (*c == ';') {
	  *c = 0 ;
	  break ;
	}

      if (!strstr(lcbuf, lctype)) {
	/* don't filter this content type */
	ap_filter_t* fnext = f->next ;
	ap_remove_output_filter(f) ;
	return ap_pass_brigade(fnext, bb) ;
      }
    }

    ctx = f->ctx = apr_palloc(f->r->pool, sizeof(line_edit_ctx)) ;
    ctx->bbsave = apr_brigade_create(f->r->pool, f->c->bucket_alloc) ;

    ctx->rewriterules = apr_array_make(f->r->pool,
            cfg->rewriterules->nelts, sizeof(rewriterule));

#define RLOG(_l,_r,_msg,...) do{\
        if(cfg->verbose) \
            ap_log_rerror(APLOG_MARK,APLOG_##_l,0,_r,_msg,##__VA_ARGS__);\
    }while(0)
#define RDEBUG(_r,_msg,...) RLOG(INFO,_r,_msg,##__VA_ARGS__)

    for (i = 0; i < cfg->rewriterules->nelts; ++i) {
        RDEBUG(f->r,"LERewriteRule: from: %s  to: %s", rules[i].from_save,rules[i].to) ;
        if(rules[i].cond) {
            rewriterule *p = &rules[i];
            int has_cond = -1;
            const char *thisval = apr_table_get(f->r->subprocess_env, p->cond->env);
            RDEBUG(f->r, "  cond: %s, %s", rules[i].cond->env,rules[i].cond->val?rules[i].cond->val:"") ;
            if (!p->cond->val) {
                /* required to be "anything" */
                if (thisval)
                    has_cond = 1;	/* satisfied */
                else
                    has_cond = 0;	/* unsatisfied */
            } else {
                if (thisval && !strcasecmp(p->cond->val, thisval)) {
                    has_cond = 1;	/* satisfied */
                } else {
                    has_cond = 0;	/* unsatisfied */
                }
            }
            if (((has_cond == 0) && (p->cond->rel ==1 ))
                    || ((has_cond == 1) && (p->cond->rel == -1))) {
                RDEBUG(f->r, "      : filtered") ;
                continue;  /* condition is unsatisfied */
            }
        }
        if (rules[i].flags & M_START)
            ctx->rulestart = newrule = apr_pcalloc(f->r->pool,sizeof(*newrule));
        else if(rules[i].flags & M_END)
            ctx->ruleend = newrule = apr_pcalloc(f->r->pool,sizeof(*newrule));
        else
            newrule = apr_array_push (((line_edit_ctx*)ctx)->rewriterules) ;
        *newrule = rules[i];

	if (rules[i].flags & M_ENV) 
	  newrule->to = interpolate_env(f->r, rules[i].to);

        if (rules[i].flags & M_ENV_FROM) {
	  newrule->from_save = interpolate_env(f->r, rules[i].from_save);
          if(compile_rule(f->r->pool,newrule)) {
              ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
                      "reg compile failed for: %s", newrule->from_save) ;
              /* bail out*/
              ap_filter_t* fnext = f->next ;
              ap_remove_output_filter(f) ;
              return ap_pass_brigade(fnext, bb) ;
          }
	}
    }
    /* for back-compatibility with Apache 2.0, set some protocol stuff */
    apr_table_unset(f->r->headers_out, "Content-Length") ;
    apr_table_unset(f->r->headers_out, "Content-MD5") ;
    apr_table_unset(f->r->headers_out, "Accept-Ranges") ;
  }
  /* by now our rules are in ctx->rewriterules */
  rules = (rewriterule*) ctx->rewriterules->elts ;

  /* bbline is what goes to the next filter,
   * so we (can) have a new one each time.
   */
  bbline = apr_brigade_create(f->r->pool, f->c->bucket_alloc) ;

  /* Since we now support arbitary line start and line end using
   * regex, we need some way to skip any non matching characters
   * in between end and start. We use the following marker to mark
   * the bucket before passing to bbline
   */
  static apr_bucket_type_t s_pool_skip, s_heap_skip, 
    s_trans_skip, s_immortal_skip;
  if(s_pool_skip.name == NULL) {
      s_pool_skip = apr_bucket_type_pool;
      s_heap_skip = apr_bucket_type_heap;
      s_trans_skip = apr_bucket_type_transient;
      s_immortal_skip = apr_bucket_type_immortal;
#define BUCKET_CAN_SKIP(e) (APR_BUCKET_IS_TRANSIENT(e) ||\
        APR_BUCKET_IS_HEAP(e) || \
        APR_BUCKET_IS_POOL(e) || \
        APR_BUCKET_IS_IMMORTAL(e))
#define BUCKET_IS_SKIPPED(e) ((e)->type==&s_trans_skip || \
        (e)->type==&s_heap_skip || \
        (e)->type==&s_pool_skip || \
        (e)->type==&s_immortal_skip)
#define RDEBUG_BUCKET(e,msg,...) do{\
        if(cfg->verbose) {\
            const char *_buf;\
            apr_size_t _bytes;\
            if (apr_bucket_read(e, &_buf, &_bytes, APR_BLOCK_READ)==APR_SUCCESS){\
                char *_s = apr_pstrndup(f->r->pool,_buf,_bytes);\
                ap_log_rerror(APLOG_MARK,APLOG_INFO,0,f->r,msg " bucket: %s",##__VA_ARGS__,_s);\
            }else\
                ap_log_rerror(APLOG_MARK,APLOG_ERR,0,f->r,"bucket failed to read");\
        }\
      }while(0)
#define BUCKET_MOVE_(a,d,e) do {\
        apr_bucket *_b = APR_BUCKET_NEXT(e);\
        RDEBUG_BUCKET(e,#a " " #d);\
        APR_BUCKET_REMOVE(e);\
        APR_BRIGADE_INSERT_TAIL(d, e);\
        e = _b;\
      }while(0)
#define BUCKET_MOVE(d,e) BUCKET_MOVE_(move,d,e)
#define BUCKET_SKIP(e) do {\
        if(APR_BUCKET_IS_TRANSIENT(e))\
            (e)->type = &s_trans_skip;\
        else if(APR_BUCKET_IS_HEAP(e))\
            (e)->type = &s_heap_skip;\
        else if(APR_BUCKET_IS_POOL(e))\
            (e)->type = &s_pool_skip;\
        else if(APR_BUCKET_IS_IMMORTAL(e)) \
            (e)->type = &s_immortal_skip;\
        BUCKET_MOVE_(skip,bbline,e);\
      }while(0)
  }
  /* first ensure we have no mid-line breaks that might be in the
   * middle of a search string causing us to miss it!  At the same
   * time we split into lines to avoid pattern-matching over big
   * chunks of memory.
   */
  while ( b != APR_BRIGADE_SENTINEL(bb) ) {
    if ( !APR_BUCKET_IS_METADATA(b) ) {
      bytes = 0;
      if ( apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ) == APR_SUCCESS ) {
	if ( bytes == 0 ) {
	  APR_BUCKET_REMOVE(b) ;
        }else if(!BUCKET_CAN_SKIP(b)) {
          RLOG(WARNING,f->r, "bypass unknown bucket: %s", b->type->name?b->type->name:"?") ;
          ctx->pending = 0;
          check_save(f,&b,&buf,&bytes);
          BUCKET_MOVE(bbline,b);
          continue;
	} else while ( bytes > 0 ) {
          if(ctx->rulestart && ctx->pending != f->r) {
            ctx->offs = 0;
            if(check_save(f,&b,&buf,&bytes)) break;
            if(!(ctx->rulestart->flags & M_REGEX)) {
                subs=apr_strmatch(ctx->rulestart->from.s, buf, bytes);
                if(subs == NULL) 
                    /* no match, save some data for next round match*/
                    match = bytes<=ctx->rulestart->length?0:(bytes-ctx->rulestart->length);
                else
                    match = (size_t)subs - (size_t)buf;
                if(match) {
                    apr_bucket_split(b, match) ;
                    BUCKET_SKIP(b);
                }
                if(subs){
                    ctx->pending = f->r;
                    ctx->offs = ctx->rulestart->length;
                }else
                    BUCKET_MOVE(ctx->bbsave,b);
                break;
            }else if((rc=pcre_exec((const pcre*)ctx->rulestart->from.r->re_pcre,0,
                        buf,bytes,0,PCRE_PARTIAL,(int*)pmatch,nmatch*3))>=0 || 
                      rc == PCRE_ERROR_PARTIAL){
                if((match = pmatch[0].rm_so)) {
                    apr_bucket_split(b, match) ;
                    BUCKET_SKIP(b);
                }
                if(rc != PCRE_ERROR_PARTIAL){
                    ctx->pending = f->r;
                    ctx->offs = pmatch[0].rm_eo - match;
                }else
                    BUCKET_MOVE(ctx->bbsave,b);
                break;
            }else{
                BUCKET_SKIP(b);
                break;
            }
          }

          if(ctx->ruleend) {
            int found = 0;
            if(check_save(f,&b,&buf,&bytes)) break;
            match = 0;
            if(ctx->ruleend->flags & M_REGEX){
                if(ctx->offs<0) ctx->offs = 0;
                if((rc=pcre_exec((const pcre*)ctx->ruleend->from.r->re_pcre,0,
                    buf+ctx->offs,bytes-ctx->offs,0,PCRE_PARTIAL,(int*)pmatch,nmatch*3))>=0)
                {
                    found = 1;
                    if(ctx->ruleend->flags & M_EXCLUSIVE)
                        match = pmatch[0].rm_so+ctx->offs;
                    else
                        match = pmatch[0].rm_eo+ctx->offs;
                }
            }else if((subs=apr_strmatch(ctx->ruleend->from.s, buf+ctx->offs, bytes-ctx->offs))){
                found = 1;
                match = (size_t)subs - (size_t)buf + ctx->offs;
                if(!(ctx->ruleend->flags & M_EXCLUSIVE))
                    match += ctx->ruleend->length;
            }
            ctx->offs = 0;
            if(found){
                if(match) apr_bucket_split(b, match) ;
                /*in case previous offs==-1, we still have dangling content in bbsave*/
                check_save(f,&b,&buf,&bytes);
                BUCKET_MOVE(bbline,b);
                ctx->pending = 0;
                break;
            }
            if(ctx->ruleend->flags & M_REGEX) {
                if(rc == PCRE_ERROR_PARTIAL)
                    ctx->offs += pmatch[0].rm_so;
                else
                    ctx->offs = -1;
            }else if(bytes > ctx->ruleend->length)
                ctx->offs = bytes - ctx->ruleend->length;
            BUCKET_MOVE(ctx->bbsave,b);
            break;
          }

	  switch (cfg->lineend) {

	  case LINEEND_UNIX:
	    le = memchr(buf, '\n', bytes) ;
	    break ;

	  case LINEEND_MAC:
	    le = memchr(buf, '\r', bytes) ;
	    break ;

	  case LINEEND_DOS:
	    /* Edge-case issue: if a \r\n spans buckets it'll get missed.
	     * Not a problem for present purposes, but would be an issue
	     * if we claimed to support pattern matching on the lineends.
	     */
	    found = 0 ;
	    le = memchr(buf+1, '\n', bytes-1) ;
	    while ( le && !found ) {
	      if ( le[-1] == '\r' ) {
	        found = 1 ;
	      } else {
	        le = memchr(le+1, '\n', bytes-1 - (le+1 - buf)) ;
	      }
	    }
	    if ( !found )
	      le = 0 ;
	    break;

	  case LINEEND_ANY:
	  case LINEEND_UNSET:
	    /* Edge-case notabug: if a \r\n spans buckets it'll get seen as
	     * two line-ends.  It'll insert the \n as a one-byte bucket.
	     */
	    le_n = memchr(buf, '\n', bytes) ;
	    le_r = memchr(buf, '\r', bytes) ;
	    if ( le_n != NULL )
	      if ( le_n == le_r + sizeof(char))
	        le = le_n ;
	      else if ( (le_r < le_n) && (le_r != NULL) )
	        le = le_r ;
	      else
	        le = le_n ;
	    else
	      le = le_r ;
	    break;

	  case LINEEND_NONE:
	    le = 0 ;
	    break;

	  case LINEEND_CUSTOM:
	    le = memchr(buf, cfg->lechar, bytes) ;
	    break;
	  }
	  if ( le ) {
	    /* found a lineend in this bucket. */
	    offs = 1 + ((size_t)le-(size_t)buf) / sizeof(char) ;
	    apr_bucket_split(b, offs) ;
	    bytes -= offs ;
	    buf += offs ;
	    b1 = APR_BUCKET_NEXT(b) ;
	    APR_BUCKET_REMOVE(b);

	    /* Is there any previous unterminated content ? */
	    if ( !APR_BRIGADE_EMPTY(ctx->bbsave) ) {
	      /* append this to any content waiting for a lineend */
	      APR_BRIGADE_INSERT_TAIL(ctx->bbsave, b) ;
	      rv = apr_brigade_pflatten(ctx->bbsave, &fbuf, &fbytes, f->r->pool) ;
	      /* make b a new bucket of the flattened stuff */
	      b = apr_bucket_pool_create(fbuf, fbytes, f->r->pool,
			f->r->connection->bucket_alloc) ;

	      /* bbsave has been consumed, so clear it */
	      apr_brigade_cleanup(ctx->bbsave) ;
	    }
	    /* b now contains exactly one line */
	    APR_BRIGADE_INSERT_TAIL(bbline, b);
	    b = b1 ;
            ctx->pending = 0;
	  } else {
	    /* no lineend found.  Remember the dangling content */
	    APR_BUCKET_REMOVE(b);
	    APR_BRIGADE_INSERT_TAIL(ctx->bbsave, b);
	    bytes = 0 ;
	  }
	} /* while bytes > 0 */
      } else {
	/* bucket read failed - oops !  Let's remove it. */
	APR_BUCKET_REMOVE(b);
      }
    } else if ( APR_BUCKET_IS_EOS(b) ) {
      /* If there's data to pass, send it in one bucket */
      if ( !APR_BRIGADE_EMPTY(ctx->bbsave) ) {
        rv = apr_brigade_pflatten(ctx->bbsave, &fbuf, &fbytes, f->r->pool) ;
        b1 = apr_bucket_pool_create(fbuf, fbytes, f->r->pool,
		f->r->connection->bucket_alloc) ;
        b1->type = &s_pool_skip;
        RDEBUG_BUCKET(b1,"flush");
        APR_BRIGADE_INSERT_TAIL(bbline, b1);
        ctx->pending = 0;
        ctx->offs = 0;
      }
      apr_brigade_cleanup(ctx->bbsave) ;
      /* start again rather than segfault if a seriously buggy
       * filter in front of us sent a bogus EOS
       */
      f->ctx = NULL ;

      /* move the EOS to the new brigade */
      APR_BUCKET_REMOVE(b);
      APR_BRIGADE_INSERT_TAIL(bbline, b);
    } else {
      /* chop flush or unknown metadata bucket types */
      apr_bucket_delete(b);
    }
    /* OK, reset pointer to what's left (since we're not in a for-loop) */
    b = APR_BRIGADE_FIRST(bb) ;
  }

  /* OK, now we have a bunch of complete lines in bbline,
   * so we can apply our edit rules
   */

  /* When we get a match, we split the line into before+match+after.
   * To flatten that back into one buf every time would be inefficient.
   * So we treat it as three separate bufs to apply future rules.
   *
   * We can only reasonably do that by looping over buckets *inside*
   * the loop over rules.
   *
   * That means concepts like one-match-per-line or start-of-line-only
   * won't work, except for the first rule.  So we won't pretend.
   */
  for (i = 0; i < ctx->rewriterules->nelts; ++i) {
    for ( b = APR_BRIGADE_FIRST(bbline) ;
	b != APR_BRIGADE_SENTINEL(bbline) ;
	b = APR_BUCKET_NEXT(b) ) {
      if ( !APR_BUCKET_IS_METADATA(b) && !BUCKET_IS_SKIPPED(b)
	&& (apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ) == APR_SUCCESS)) {
	if ( rules[i].flags & M_REGEX ) {
          bufp = buf;
          /* Apache's ap_regexec is kinda dumb, because it demands a null 
           * terminated string, while the actual worker pcre_exec only needs
           * the string length. Better use pcre_exec directly.
           */
          while((rc=pcre_exec((const pcre*)rules[i].from.r->re_pcre,0,
                  bufp,bytes,0,0,(int*)pmatch,nmatch*3))>=0 ){
            if(rc==0) rc = nmatch;
	    match = pmatch[0].rm_so ;
	    subs = ap_pregsub(f->r->pool, rules[i].to, bufp, rc, pmatch) ;
            if(match) {
                apr_bucket_split(b, match) ;
                b = APR_BUCKET_NEXT(b) ;
            }
            if(pmatch[0].rm_eo < bytes)
                apr_bucket_split(b, pmatch[0].rm_eo - match) ;
            RDEBUG_BUCKET(b,"replace %s -> %s,",rules[i].from_save,subs);
            b1 = APR_BUCKET_NEXT(b) ;
            apr_bucket_delete(b) ;
	    b = apr_bucket_pool_create(subs, strlen(subs), f->r->pool,
		  f->r->connection->bucket_alloc) ;
            b->type = &s_pool_skip;
	    APR_BUCKET_INSERT_BEFORE(b1, b) ;
            b = b1;
	    bufp += pmatch[0].rm_eo ;
            bytes -= pmatch[0].rm_eo ;
	  }
	} else {
	  bufp = buf ;
	  while (subs = apr_strmatch(rules[i].from.s, bufp, bytes), subs != NULL) {
	    match = (size_t)subs - (size_t)bufp;
            if(match) {
                bytes -= match ;
                bufp += match ;
                apr_bucket_split(b, match) ;
                b = APR_BUCKET_NEXT(b) ;
            }
            if(rules[i].length < bytes)
                apr_bucket_split(b, rules[i].length) ;
            RDEBUG_BUCKET(b,"replace %s -> %s,",rules[i].from_save,rules[i].to);
            b1 = APR_BUCKET_NEXT(b) ;
	    apr_bucket_delete(b) ;
	    bytes -= rules[i].length ;
	    bufp += rules[i].length ;
	    b = apr_bucket_immortal_create(rules[i].to, rules[i].to_length,
		f->r->connection->bucket_alloc) ;
            b->type = &s_immortal_skip;
	    APR_BUCKET_INSERT_BEFORE(b1, b) ;
            b = b1;
	  }
	}
      }
    }
  }

  /* now pass it down the chain */
  rv = ap_pass_brigade(f->next, bbline) ;

  /* if we have leftover data, don't risk it going out of scope */
  for ( b = APR_BRIGADE_FIRST(ctx->bbsave) ;
	b != APR_BRIGADE_SENTINEL(ctx->bbsave) ;
	b = APR_BUCKET_NEXT(b)) {
    apr_bucket_setaside(b, f->r->pool) ;
  }

  return rv ;
}
static int line_edit(apr_pool_t* pool, apr_pool_t* p1,
		apr_pool_t* p2, server_rec* s) {
  ap_add_version_component(pool, "Line-Edit/" LINE_EDIT_VERSION) ;
  return DECLINED ;
}

static void line_edit_hooks(apr_pool_t* pool) {
  ap_register_output_filter_protocol(line_edit_filter_name, line_edit_filter,
		NULL, AP_FTYPE_RESOURCE,
		AP_FILTER_PROTO_CHANGE|AP_FILTER_PROTO_CHANGE_LENGTH) ;
  ap_hook_post_config(line_edit, NULL, NULL, APR_HOOK_MIDDLE) ;
}

static const char* line_edit_lineend(cmd_parms* cmd,
		void* cfg, const char* arg, const char *ch) {
  line_edit_cfg* fcfg = cfg ;
  if (!strcasecmp(arg, "unix")) {
    fcfg->lineend = LINEEND_UNIX ;
  } else if (!strcasecmp(arg, "dos")) {
    fcfg->lineend = LINEEND_DOS ;
  } else if (!strcasecmp(arg, "mac")) {
    fcfg->lineend = LINEEND_MAC ;
  } else if (!strcasecmp(arg, "any")) {
    fcfg->lineend = LINEEND_ANY ;
  } else if (!strcasecmp(arg, "none")) {
    fcfg->lineend = LINEEND_NONE ;
  } else if (!strcasecmp(arg, "custom")) {
    if (ch) {
      fcfg->lineend = LINEEND_CUSTOM ;
      fcfg->lechar = ch[0];
    }
    else {
      return "You must specify the custom lineend character.";
    }
  } else {
    return "Unknown lineend scheme";
  }
  return NULL;
}

#define REGFLAG(n,s,c) ( (s&&(ap_strchr((char*)(s),(c))!=NULL)) ? (n) : 0 )
static const char* line_edit_rewriterule(cmd_parms* cmd, void* cfg, const char *args) {
  rewriterule* rule = apr_array_push (((line_edit_cfg*)cfg)->rewriterules) ;
  const char* usage =
	"Usage: LERewriteRule from-pattern to-pattern [flags] [cond]";
  const char* from;
  const char* to;
  const char* flags;
  const char* cond = NULL;
  
  if (from = ap_getword_conf(cmd->pool, &args), !from)
    return usage;
  if (to = ap_getword_conf(cmd->pool, &args), !to)
    return usage;
  flags = ap_getword_conf(cmd->pool, &args);
  if (flags && *flags)
    cond = ap_getword_conf(cmd->pool, &args);
  if (cond && !*cond)
    cond = NULL;

  if (cond != NULL) {
    char *eq;
    char* cond_copy;
    rule->cond = apr_pcalloc(cmd->pool, sizeof(rewritecond));
    if (cond[0] == '!') {
      rule->cond->rel = -1;
      rule->cond->env = cond_copy = apr_pstrdup(cmd->pool, cond+1);
    } else {
      rule->cond->rel = 1;
      rule->cond->env = cond_copy = apr_pstrdup(cmd->pool, cond);
    }
    eq = ap_strchr(++cond_copy, '=');
    if (eq) {
      *eq = 0;
      rule->cond->val = eq+1;
    }
  } else {
    rule->cond = NULL;
  }

  rule->from_save = from;
  rule->to = to ;
  if ( flags ) {
    rule->flags
	= REGFLAG(M_REGEX, flags, 'R')
	| REGFLAG(M_NOCASE, flags, 'i')
	| REGFLAG(M_NEWLINE, flags, 'm')
	| REGFLAG(M_ENV, flags, 'V')
	| REGFLAG(M_ENV_FROM, flags, 'v')
	| REGFLAG(M_START, flags, 's')
	| REGFLAG(M_END, flags, 'e')
	| REGFLAG(M_END_EX, flags, 'E')
	;
  } else {
    rule->flags = 0 ;
  }
  if(!(rule->flags & M_ENV_FROM)) {
      if(compile_rule(cmd->pool,rule)){
          ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
                  "failed to compile rule: %s", rule->from_save) ;
          return usage;
      }
  }
  return NULL;
}

static const command_rec line_edit_cmds[] = {
  AP_INIT_TAKE12("LELineEnd", line_edit_lineend, NULL, OR_ALL,
	"Use line ending: UNIX|MAC|DOS|ANY|NONE|CUSTOM [char]") ,
  AP_INIT_RAW_ARGS("LERewriteRule", line_edit_rewriterule, NULL,
	RSRC_CONF|ACCESS_CONF, "Line-oriented text rewrite rule: From, To [, Flags] [cond]") ,
  AP_INIT_FLAG("LEVerbose", ap_set_flag_slot,
          (void*)APR_OFFSETOF(line_edit_cfg, verbose),
          RSRC_CONF|ACCESS_CONF, "Turn on verbose log" ) ,
  {NULL}
} ;
static void* line_edit_cr_cfg(apr_pool_t* pool, char* x) {
  line_edit_cfg* ret = apr_palloc(pool, sizeof(line_edit_cfg)) ;
  ret->lineend = LINEEND_UNSET;
  ret->rewriterules = apr_array_make(pool, 8, sizeof(rewriterule)) ;
  ret->lechar = 0;
  return ret ;
}
static void* line_edit_merge(apr_pool_t* pool, void* BASE, void* ADD) {
  line_edit_cfg* base = (line_edit_cfg*) BASE ;
  line_edit_cfg* add = (line_edit_cfg*) ADD ;
  line_edit_cfg* conf = apr_palloc(pool, sizeof(line_edit_cfg)) ;

  conf->lineend = (add->lineend == LINEEND_UNSET)
	  ? base->lineend
	  : add->lineend ;
  conf->rewriterules
	  = apr_array_append(pool, base->rewriterules, add->rewriterules) ;
  conf->lechar = (add->lechar == 0) ? base->lechar : add->lechar;
  conf->verbose = add->verbose ? 1 : base->verbose;
  return conf ;
}

module AP_MODULE_DECLARE_DATA line_edit_module = {
  STANDARD20_MODULE_STUFF,
  line_edit_cr_cfg ,
  line_edit_merge ,
  NULL ,
  NULL ,
  line_edit_cmds ,
  line_edit_hooks
};
