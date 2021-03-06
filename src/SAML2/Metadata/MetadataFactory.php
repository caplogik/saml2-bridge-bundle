<?php

/**
 * Copyright 2014 SURFnet bv
 *
 * Modifications copyright (C) 2017 Adactive SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace AdactiveSas\Saml2BridgeBundle\SAML2\Metadata;


use AdactiveSas\Saml2BridgeBundle\Entity\HostedEntities;
use Symfony\Component\Routing\RouterInterface;
use Twig\Environment;

class MetadataFactory
{
    /**
     * @var \Symfony\Component\Templating\Environment
     */
    private $twig;

    /**
     * @var HostedEntities
     */
    private $hostedEntities;

    /**
     * MetadataFactory constructor.
     * @param Environment $twig
     * @param HostedEntities $hostedEntities
     */
    public function __construct(
        Environment $twig,
        HostedEntities $hostedEntities
    ) {
        $this->twig = $twig;
        $this->hostedEntities = $hostedEntities;
    }

    /**
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function getMetadataResponse()
    {
        $response = new Response();

        $response->setContent($this->twig->render(
            "AdactiveSasSaml2BridgeBundle:Metadata:metadata.xml.twig",
            [
                "metadata" => $this->buildMetadata()
            ]
        ));

        $response->headers->set('Content-Type', 'xml');

        return $response;
    }

    /**
     * @return Metadata
     */
    public function buildMetadata(){
        $metadata = new Metadata();

        $metadata->entityId = $this->hostedEntities->getEntityId();

        if($this->hostedEntities->hasIdentityProvider()){
            $idp = $this->hostedEntities->getIdentityProvider();

            $idpMetadata = new IdentityProviderMetadata();
            $idpMetadata->ssoUrl = $idp->getSsoUrl();
            $idpMetadata->slsUrl = $idp->getSlsUrl();

            $metadata->idp = $idpMetadata;
        }

        return $metadata;
    }
}
