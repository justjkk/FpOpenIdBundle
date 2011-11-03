<?php
namespace Fp\OpenIdBundle\Security\Core\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Routing\RouterInterface;

use Fp\OpenIdBundle\Security\Core\Authentication\Token\TokenPersister;
use Fp\OpenIdBundle\Security\Core\Authentication\Token\OpenIdToken;
use Fp\OpenIdBundle\Consumer\ConsumerProvider;


class OpenIdAuthenticationProvider implements AuthenticationProviderInterface
{
    protected $consumerProvider;

    protected $router;

    protected $tokenPersister;

    protected $parameters;

    public function __construct(ConsumerProvider $consumerProvider, RouterInterface $router, array $parameters)
    {
        $this->consumerProvider = $consumerProvider;
        $this->router = $router;

        $this->parameters = array_merge(array(
            'return_route' => null,
            'approve_route' => null,
            'roles' => array()), $parameters);
    }

    public function authenticate(TokenInterface $token)
    {
        if (false == $this->supports($token)) {
            return null;
        }

        $processState = 'process' . ucfirst($token->getState());

        return $this->$processState($token);
    }

    public function supports(TokenInterface $token)
    {
        if (false == ($token instanceof OpenIdToken)) {
            return false;
        }

        return in_array($token->getState(), array('verify', 'complete', 'approved'));
    }

    public function processVerify(OpenIdToken $token)
    {
        $consumer = $this->consumerProvider->provide($token->getIdentifier());

        $token->setAuthenticateUrl(
            $consumer->authenticateUrl($token->getIdentifier(), $this->getReturnUrl()));

        return $token;
    }

    public function processComplete(OpenIdToken $token)
    {
        $consumer = $this->consumerProvider->provide($token->getIdentifier());

        $attributes = $consumer->complete($token->getResponse(), $this->getReturnUrl());

        $token = new OpenIdToken($attributes['identity'], $this->parameters['roles']);
        $token->setAttributes($attributes);

        if ($this->parameters['approve_route']) {
            $token = new OpenIdToken($attributes['identity'], $this->parameters['roles'], false);
            $token->setAttributes($attributes);
            $token->setApproveUrl($this->router->generate($this->parameters['approve_route'], array(), true));
        } else {
            $token = new OpenIdToken($attributes['identity'], $this->parameters['roles']);
            $token->setAttributes($attributes);
        }

        return $token;
    }

    public function processApproved(OpenIdToken $approvedToken)
    {
        $token = new OpenIdToken($approvedToken->getIdentifier(), $approvedToken->getRoles());
        $token->setUser($approvedToken->getUser());

        return $token;
    }

    protected function getReturnUrl()
    {
        $route = $this->parameters['return_route'];

        return $this->router->generate($route, array(), true);
    }
}