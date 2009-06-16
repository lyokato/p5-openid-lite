package OpenID::Lite::RelyingParty::Discover::Fetcher::XRI;

use Any::Moose;
with 'OpenID::Lite::Role::ErrorHandler';
with 'OpenID::Lite::Role::AgentHandler';

has 'proxy_url' => (
    is  => 'rw',
    isa => 'Str',
);

use XRI::Resolution::Lite;
use OpenID::Lite::RelyingParty::Discover::FetchResult;
use OpenID::Lite::Constants::Yadis qw(XRDS_CONTENT_TYPE);

sub fetch {
    my ( $self, $iname, $option ) = @_;
    my %params;
    $params{ua}       = $self->agent     if $self->agent;
    $params{resolver} = $self->proxy_url if $self->proxy_url;
    my $r = XRI::Resolution::Lite->new( {%params} );
    my $xrds;
    eval {
        #XXX: XRI::Resolution::Lite handle type wrongly?
        #     Accept Header shouldn't be 'type' but 'format'.
        $xrds = $r->resolve( $iname,
            { format => XRDS_CONTENT_TYPE, type => $option->{service_type} } );
    };
    if ($@) {
        return $self->ERROR( sprintf q{Failed to resolve XRI iname "%s": %s},
            $iname, $@ );
    }
    my $result = OpenID::Lite::RelyingParty::Discover::FetchResult->new;
    $result->content_type( XRDS_CONTENT_TYPE );
    $result->normalized_identifier($iname);
    $result->xrds($xrds);
    return $result;
}

no Any::Moose;
__PACKAGE__->meta->make_immutable;
1;

