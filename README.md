This is a fork of apache mod_line_edit from webthing (http://apache.webthing.com/mod_line_edit/). 

Main focus is to make this more efficient for searching and replacing absolute URL, which does not really need a context aware parser. For relative URL, it is best to use a module with parser like mod_proxy_html.

Planed modification:

* Allow at most one match per position. Original implementation split a matched line as three lines, before + matched + after. And the rest rules will be applyed to these new lines, too, which may cause multiple match and sustitution in the same position. This is clearly not users' intention.
* Add 'from' interpolate to LERewriteRule
* Add 'cond' to LERewriteRule just like ProxyHTMLURLMap in mod_proxy_html
* Allow multiple line-end character. For URL match, any illeagal character can be consider as line-end.
* Add string marker(s) as line-start, e.g. http://. Probably implement as a new flag to LERewriteRule to make it a special rule.
