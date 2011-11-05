use Test::More;

use strict;
use warnings;

BEGIN { use_ok('Net::DNS::Sinkhole::Handler::Whitelist'); }

my $whitelist_handler = new_ok( 'Net::DNS::Sinkhole::Handler::Whitelist');
isa_ok( $whitelist_handler, 'Net::DNS::Sinkhole::Handler' );

can_ok( 'Net::DNS::Sinkhole::Handler::Whitelist', 'handler' );

$whitelist_handler->trie->add("microsoft.com");
my ( $rcode) = $whitelist_handler->handler("www.microsoft.com");
is($rcode,"NOERROR","Whitelisted domain lookup success");

( $rcode ) = $whitelist_handler->handler("www.richardharman.com");
is($rcode,"IGNORE","Non-whitelisted domain lookup ignored");

done_testing();
