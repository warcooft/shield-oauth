<?php

declare(strict_types=1);

namespace Datamweb\ShieldOAuth\Libraries;

use CodeIgniter\HTTP\CURLRequest;
use Config\Services;
use Datamweb\ShieldOAuth\Config\ShieldOAuthConfig;
use Datamweb\ShieldOAuth\Libraries\Basic\AbstractOAuth;
use Exception;

class MicrosoftOAuth extends AbstractOAuth
{
    private static string $API_CODE_URL      = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
    private static string $API_TOKEN_URL     = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
    private static string $API_USER_INFO_URL = 'https://graph.microsoft.com/v1.0/me';
    private static string $APPLICATION_NAME  = 'ShieldOAuth';
    protected string $token;
    protected CURLRequest $client;
    protected ShieldOAuthConfig $config;
    protected string $client_id;
    protected string $client_secret;
    protected string $callback_url;

    public function __construct(string $token = '')
    {
        $this->token         = $token;
        $this->client        = Services::curlrequest();
        $this->config        = config('ShieldOAuthConfig');
        $this->callback_url  = base_url('oauth/' . $this->config->call_back_route);
        $this->client_id     = env('ShieldOAuthConfig.microsoft.client_id', $this->config->oauthConfigs['microsoft']['client_id']);
        $this->client_secret = env('ShieldOAuthConfig.microsoft.client_secret', $this->config->oauthConfigs['microsoft']['client_secret']);
    }

    public function makeGoLink(string $state): string
    {
        $query = http_build_query([
            'client_id'       => $this->client_id,
            'response_type'   => 'code',
            'redirect_uri'    => $this->callback_url,
            'response_mode'   => 'query',
            'approval_prompt' => 'auto',
            'scope'           => 'User.Read',
            'state'           => $state,
            'sso_reload'      => true,
        ]);

        return self::$API_CODE_URL . '?' . $query;
    }

    /**
     * @param array<string, string> $allGet
     */
    public function fetchAccessTokenWithAuthCode(array $allGet): void
    {
        try {
            $response = $this->client->request('POST', self::$API_TOKEN_URL, [
                'form_params' => [
                    'client_id'     => $this->client_id,
                    'client_secret' => $this->client_secret,
                    'code'          => $allGet['code'],
                    'redirect_uri'  => $this->callback_url,
                    'grant_type'    => 'authorization_code',
                ],
                'headers' => [
                    'User-Agent' => self::$APPLICATION_NAME . '/1.0',
                    'Accept'     => 'application/json',
                ],
            ]);
        } catch (Exception $e) {
            exit($e->getMessage());
        }

        $token = json_decode($response->getBody())->access_token;

        $this->setToken($token);
    }

    public function fetchUserInfoWithToken(): object
    {
        try {
            $response = $this->client->request('GET', self::$API_USER_INFO_URL, [
                'headers' => [
                    'Accept'        => 'application/json',
                    'User-Agent'    => self::$APPLICATION_NAME . '/1.0',
                    'Authorization' => 'Bearer ' . $this->getToken(),
                ],
                'http_errors' => false,
            ]);
        } catch (Exception $e) {
            exit($e->getMessage());
        }

        $userInfo = json_decode($response->getBody());

        $userInfo->email = $userInfo->mail;

        return $userInfo;
    }

    public function setColumnsName(string $nameOfProcess, object $userInfo): array
    {
        if ($nameOfProcess === 'syncingUserInfo') {
            return [
                $this->config->usersColumnsName['first_name'] => $userInfo->givenName,
                $this->config->usersColumnsName['last_name']  => $userInfo->surname ?? null,
                $this->config->usersColumnsName['avatar']     => null,
            ];
        }

        if ($nameOfProcess === 'newUser') {
            return [
                'username'                                    => $userInfo->mail,
                'email'                                       => $userInfo->mail,
                'password'                                    => bin2hex(random_bytes(16)),
                'active'                                      => 1, // if microsoft authentication is valid then the user account does not require an email activator
                $this->config->usersColumnsName['first_name'] => $userInfo->givenName,
                $this->config->usersColumnsName['last_name']  => $userInfo->surname ?? null,
                $this->config->usersColumnsName['avatar']     => null,
            ];
        }

        return [];
    }
}
