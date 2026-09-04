<?php
require_once __DIR__ . '/helpers.php';

lk_index_page(
    gqlab(),
    gq_levels(),
    'A GraphQL server validates that a document is well formed and that every field exists on the type it is
     selected on. That is the whole of what the language guarantees. Authorisation lives in resolvers, rate
     limits live in middleware, and depth limits live in a static analyser - three separate places that each
     model the request slightly differently. These ten levels live in the gaps between them, from an endpoint
     that describes itself on request to a chain that turns a discovery bug into an admin read.',
    '<strong>Everything here runs on a real engine.</strong> <code>graphql.php</code> is a hand-written lexer,
     parser, validator and executor: aliases, fragments, variables, introspection and a depth counter all behave
     the way the specification says, which is what makes the bugs in these levels reproducible rather than
     staged. Each level page has a query editor, a few starter documents that already parse, and a trace showing
     what the guard inspected, what the counter measured, and which resolvers actually ran.'
);
