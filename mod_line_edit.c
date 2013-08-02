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
} line_edit_cfg ;

module AP_MODULE_DECLARE_DATA line_edit_module ;

static const char* const line_edit_filter_name = "line-editor" ;

typedef struct {
  apr_bucket_brigade* bbsave ;
  apr_array_header_t* rewriterules ; /* make a copy if per-request
					interpolation is wanted */
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
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			"Interpolating %s  =>  %s", var, val) ;
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
        rule->from.s = apr_strmatch_precompile(pool, rule->from_save, lflags) ;
    }
    return 0;
}
static apr_status_t line_edit_filter(ap_filter_t* f, apr_bucket_brigade* bb) {
  int i, j;
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

    for (i = 0; i < cfg->rewriterules->nelts; ++i) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
                "LERewriteRule: from: %s  to: %s", rules[i].from_save,rules[i].to) ;
        if(rules[i].cond) {
            rewriterule *p = &rules[i];
            int has_cond = -1;
            const char *thisval = apr_table_get(f->r->subprocess_env, p->cond->env);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
                "  cond: %s, %s", rules[i].cond->env,rules[i].cond->val?rules[i].cond->val:"") ;
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
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
                        "      : filtered") ;
                continue;  /* condition is unsatisfied */
            }
        }
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

  /* first ensure we have no mid-line breaks that might be in the
   * middle of a search string causing us to miss it!  At the same
   * time we split into lines to avoid pattern-matching over big
   * chunks of memory.
   */
  while ( b != APR_BRIGADE_SENTINEL(bb) ) {
    if ( !APR_BUCKET_IS_METADATA(b) ) {
      if ( apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ) == APR_SUCCESS ) {
	if ( bytes == 0 ) {
	  APR_BUCKET_REMOVE(b) ;
	} else while ( bytes > 0 ) {
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
        APR_BRIGADE_INSERT_TAIL(bbline, b1);
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
  static apr_bucket_type_t s_pool_marker, s_immortal_marker;
  if(s_pool_marker.name == NULL) {
      /* We use the marker type to mark the newly splitted "matched" buket,,
       * so that we won't apply other rules to them. 
       */
      s_pool_marker = apr_bucket_type_pool;
      s_immortal_marker = apr_bucket_type_immortal;
#define BUCKET_IS_MARKER(e) ((e)->type==&s_pool_marker || (e)->type==&s_immortal_marker)
  }
  for (i = 0; i < ctx->rewriterules->nelts; ++i) {
    for ( b = APR_BRIGADE_FIRST(bbline) ;
	b != APR_BRIGADE_SENTINEL(bbline) ;
	b = APR_BUCKET_NEXT(b) ) {
      if ( !APR_BUCKET_IS_METADATA(b) && !BUCKET_IS_MARKER(b)
	&& (apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ) == APR_SUCCESS)) {
	if ( rules[i].flags & M_REGEX ) {
          int rc;
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
	    apr_bucket_split(b, match) ;
	    b1 = APR_BUCKET_NEXT(b) ;
	    apr_bucket_split(b1, pmatch[0].rm_eo - match) ;
	    b = APR_BUCKET_NEXT(b1) ;
	    apr_bucket_delete(b1) ;
	    b1 = apr_bucket_pool_create(subs, strlen(subs), f->r->pool,
		  f->r->connection->bucket_alloc) ;
            b1->type = &s_pool_marker;
	    APR_BUCKET_INSERT_BEFORE(b, b1) ;
	    bufp += pmatch[0].rm_eo ;
            bytes -= pmatch[0].rm_eo ;
	  }
	} else {
	  bufp = buf ;
	  while (subs = apr_strmatch(rules[i].from.s, bufp, bytes),
			subs != NULL) {
	    match = ((size_t)subs - (size_t)bufp) / sizeof(char) ;
	    bytes -= match ;
	    bufp += match ;
	    apr_bucket_split(b, match) ;
	    b1 = APR_BUCKET_NEXT(b) ;
	    apr_bucket_split(b1, rules[i].length) ;
	    b = APR_BUCKET_NEXT(b1) ;
	    apr_bucket_delete(b1) ;
	    bytes -= rules[i].length ;
	    bufp += rules[i].length ;
	    b1 = apr_bucket_immortal_create(rules[i].to, strlen(rules[i].to),
		f->r->connection->bucket_alloc) ;
            b1->type = &s_immortal_marker;
	    APR_BUCKET_INSERT_BEFORE(b, b1) ;
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
