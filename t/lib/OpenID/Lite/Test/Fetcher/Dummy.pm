package OpenID::Lite::Test::Fetcher::Dummy;

use Mouse;
use OpenID::Lite::RelyingParty::Discover::FetchResult;

has 'contents' => (
    is => 'ro',
    isa => 'HashRef',
);

has 'content_type' => (
    is => 'ro',
    isa => 'Str',
);

sub fetch {
    my ( $self, $identifier ) = @_;
    my $result = OpenID::Lite::RelyingParty::Discover::FetchResult->new;
    $result->normalized_identifier($identifier);
    $result->content_type( $self->content_type );
    unless ( exists $self->contents->{$identifier} ) {
       return; 
    }
    $result->content( $self->contents->{$identifier} );
    return $result;
}

no Mouse;
__PACKAGE__->meta->make_immutable;
1;


