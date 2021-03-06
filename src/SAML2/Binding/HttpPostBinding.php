<?php

/**
 * Copyright 2017 Adactive SAS
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

namespace AdactiveSas\Saml2BridgeBundle\SAML2\Binding;


use AdactiveSas\Saml2BridgeBundle\Exception\BadRequestHttpException;
use AdactiveSas\Saml2BridgeBundle\Exception\LogicException;
use AdactiveSas\Saml2BridgeBundle\Form\SAML2ResponseForm;
use AdactiveSas\Saml2BridgeBundle\SAML2\Binding\Exception\UnsupportedBindingException;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Twig\Environment;

class HttpPostBinding extends AbstractHttpBinding implements HttpBindingInterface
{
    /**
     * @var FormFactoryInterface
     */
    protected $formFactory;

    /**
     * @var Environment
     */
    protected $twig;

    /**
     * HttpPostBinding constructor.
     * @param FormFactoryInterface $formFactory
     * @param Environment $twig
     */
    public function __construct(FormFactoryInterface $formFactory, Environment $twig)
    {
        $this->formFactory = $formFactory;
        $this->twig = $twig;
    }

    /**
     * @param \SAML2_StatusResponse $response
     * @return Response
     * @throws \Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
     * @throws \RuntimeException
     */
    public function getSignedResponse(\SAML2_StatusResponse $response)
    {
        $form = $this->getSignedResponseForm($response);

        $response = new Response();

        $response->setContent($this->twig->render(
            "@AdactiveSasSaml2Bridge/Binding/post.html.twig",
            [
                "form" => $form->createView()
            ]
        ));

        return $response;
    }

    /**
     * @param \SAML2_StatusResponse $response
     * @return Response
     * @throws \RuntimeException
     * @throws \Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
     */
    public function getUnsignedResponse(\SAML2_StatusResponse $response)
    {
        $form = $this->getUnsignedResponseForm($response);

        $response = new Response();

        $response->setContent($this->twig->render(
            "@AdactiveSasSaml2Bridge/Binding/post.html.twig",
            [
                "form" => $form->createView(),
            ]
        ));
    }

    /**
     * @param \SAML2_Request $request
     * @return Response
     * @throws \AdactiveSas\Saml2BridgeBundle\SAML2\Binding\Exception\UnsupportedBindingException
     */
    public function getUnsignedRequest(\SAML2_Request $request)
    {
        throw new UnsupportedBindingException("Unsupported binding: unsigned POST Request is not supported at the moment");
    }

    /**
     * @param Request $request
     * @return ReceivedData
     * @throws \AdactiveSas\Saml2BridgeBundle\SAML2\Binding\Exception\InvalidReceivedMessageQueryStringException
     * @throws \AdactiveSas\Saml2BridgeBundle\Exception\BadRequestHttpException
     */
    protected function getReceivedData(Request $request)
    {
        if (!$request->isMethod(Request::METHOD_POST)) {
            throw new BadRequestHttpException(sprintf(
                'Could not receive Message from HTTP Request: expected a POST method, got %s',
                $request->getMethod()
            ));
        }

        $requestParams = $request->request->all();

        return ReceivedData::fromReceivedProviderData($requestParams);
    }

    /**
     * @param \SAML2_StatusResponse $response
     * @return \Symfony\Component\Form\FormInterface
     * @throws \Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
     */
    protected function getSignedResponseForm(\SAML2_StatusResponse $response)
    {
        return $this->getResponseForm($response, true);
    }

    /**
     * @param \SAML2_StatusResponse $response
     * @return \Symfony\Component\Form\FormInterface
     * @throws \Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
     */
    protected function getUnsignedResponseForm(\SAML2_StatusResponse $response)
    {
        return $this->getResponseForm($response, false);
    }

    /**
     * @param \SAML2_StatusResponse $response
     * @param $isSign
     * @return \Symfony\Component\Form\FormInterface
     * @throws \Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
     */
    protected function getResponseForm(\SAML2_StatusResponse $response, $isSign)
    {
        if ($response->getDestination() === null) {
            throw new LogicException('Invalid destination');
        }

        $xmlDom = $isSign ? $response->toSignedXML() : $response->toUnsignedXML();

        $data = [
            'SAMLResponse' => base64_encode($xmlDom->ownerDocument->saveXML()),
        ];

        $hasRelayState = !empty($response->getRelayState());
        if ($hasRelayState) {
            $data["RelayState"] = $response->getRelayState();
        }

        return $this->formFactory->createNamed(
            "",
            SAML2ResponseForm::class,
            $data,
            [
            "has_relay_state"=> $hasRelayState,
            "destination" => $response->getDestination(),
            ]
        );
    }

    /**
     * @param string $destination
     * @param string $encodedRequest
     * @param string $relayState
     * @param \XMLSecurityKey $signatureKey
     * @return Response
     */
    protected function buildRequest($destination, $encodedRequest, $relayState, \XMLSecurityKey $signatureKey)
    {
        throw new UnsupportedBindingException("Unsupported binding: build POST Request is not supported at the moment");
    }
}
