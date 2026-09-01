# Turns MkDocs Material markdown into markdown GitLab's wiki renders.
#
# Only two constructs need it, and both would otherwise be actively misleading
# rather than merely plain:
#
#   * admonitions - `!!! danger "Title"` with a four-space indented body. GitLab
#     renders the marker as a paragraph and the indented body as a CODE BLOCK,
#     so the most important warnings in this documentation would arrive looking
#     like sample output. They become blockquotes with a bold first line.
#   * `<div class="grid cards" markdown>` - a Material layout wrapper. GitLab
#     drops the div and, because the `markdown` attribute means nothing to it,
#     can swallow what is inside. The wrapper is removed and the content left.
#
# Everything else in these pages is ordinary CommonMark and is passed through
# untouched. Written in awk because the wiki job runs in an image with git and a
# shell and nothing else.

BEGIN { inAdmonition = 0; seenBody = 0 }

# The end of an admonition body: any non-blank line that is not indented. A
# blank line is NOT the end - an admonition may have paragraphs in it - so the
# quote is closed here, when something outside it finally arrives.
inAdmonition && /^[^ \t]/ {
    inAdmonition = 0
    print ""
}

inAdmonition {
    if ($0 ~ /^[ \t]*$/) {
        # Blank lines before the first line of the body are the gap after the
        # marker, not part of it. Emitting them would put an empty quoted line
        # under every title.
        if (seenBody) {
            print ">"
        }
    } else {
        line = $0
        sub(/^    /, "", line)
        print "> " line
        seenBody = 1
    }

    next
}

# `!!! danger "Read this first"` and the `???` collapsible variant.
/^(!!!|\?\?\?\+?) [a-z-]+/ {
    type = $2
    title = ""

    if (match($0, /"[^"]*"/)) {
        title = substr($0, RSTART + 1, RLENGTH - 2)
    }

    label = toupper(substr(type, 1, 1)) substr(type, 2)

    if (title != "") {
        label = label ": " title
    }

    print "> **" label "**"
    print ">"

    inAdmonition = 1
    seenBody = 0

    next
}

/^<div class="grid cards"/ { next }
/^<\/div>$/ { next }

{ print }
