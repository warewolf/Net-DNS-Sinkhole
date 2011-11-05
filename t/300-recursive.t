use Test::More;

use strict;
use warnings;

BEGIN { use_ok('Net::DNS::Sinkhole::Handler::Recursive'); }

my $whitelist_handler = new_ok( 'Net::DNS::Sinkhole::Handler::Recursive');
isa_ok( $whitelist_handler, 'Net::DNS::Sinkhole::Handler' );

can_ok( 'Net::DNS::Sinkhole::Handler::Recursive', 'handler' );

my ( $rcode) = $whitelist_handler->handler("www.microsoft.com");
is($rcode,"NOERROR","Recursiveed domain lookup success");

done_testing();
