This is a fork of Apache [mod_line_edit](http://apache.webthing.com/mod_line_edit/) from webthing. 

Main focus is to make this more efficient for searching and replacing absolute URL, which does not really need a context aware parser. For relative URL, it is best to use a module with parser like [mod_proxy_html](http://apache.webthing.com/mod_proxy_html/).

Added feature:

* Allow at most one match per position. Original implementation split a matched line as three lines, before + matched + after. And the rest rules will be applied to these new lines, too, which may cause multiple match and substitution in the same position. This is clearly not users' intention.
* Add flag v to LERewriteRule to interpolate the 'from' part of the rule.
* Add 'cond' to LERewriteRule just like ProxyHTMLURLMap in mod_proxy_html to conditionally enable/disable rules based on environment variable. Quote from [mod_proxy_html](http://apache.webthing.com/mod_proxy_html/config.html),

>The optional cond argument specifies a condition to test before the parse. If a condition is unsatisfied, the URLMap will be ignored in this parse.
>
>The condition takes the form [!]var[=val], and is satisfied if the value of environment variable var is val. If the optional =val is omitted, then any value of var satisfies the condition, provided only it is set to something. If the first character is !, the condition is reversed.

* Added flag 's/e/E' to LERewriteRule to mark for line start/end/exclusive. The 'to' part of the rule is ignored. 'E' when combined with 's' or 'e' means to exclude the matched string when capturing the line, which is achievable with look-ahead in regular expression, but not in plain search and substitution. When line-end rule is given, LELineEnd is ignored.

