<?php

class PHParnish
{

    /**
     * Socket pointer
     * @var resource
     */
    private $fp;

    /**
     * Host on which varnishadm is listening
     * @var string
     */
    private string $host = "127.0.0.1";

    /**
     * Port on which varnishadm is listening, usually 6082
     * @var int port
     */
    private int $port = 6080;

    /**
     * Secret to use in authentication challenge.
     * @var string
     */
    private string $secret = "";


    private int $timeout = 1;

    /**
     * Constructor
     * @param array $config
     * @throws Exception
     */
    public function __construct(array $config)
    {

        if (!empty($config["host"])) {
            $this->host = $config["host"];
        }

        if (!empty($config["port"])) {
            $this->port = $config["port"];
        }

        if (!empty($config["secret"])) {
            $this->secret = $config["secret"];
        }

        if (!empty($config["timeout"])) {
            $this->timeout = $config["timeout"];
        }

        $this->connect();

    }


    public function __destruct()
    {
        $this->quit();
    }


    /**
     * Connect to admin socket
     * @return string the banner, in case you're interested
     * @throws Exception
     */
    public function connect(): string
    {

        $this->fp = fsockopen($this->host, $this->port, $errno, $errstr, $this->timeout);
        if (!is_resource($this->fp)) {
            // error would have been raised already by fsockopen
            throw new Exception(sprintf('Failed to connect to varnishadm on %s:%s; "%s"', $this->host, $this->port, $errstr));
        }

        // set socket options
        stream_set_blocking($this->fp, 1);
        stream_set_timeout($this->fp, $this->timeout);

        // connecting should give us the varnishadm banner with a 200 code, or 107 for auth challenge
        $banner = $this->read($code);
        if ($code === 107) {
            if (!$this->secret) {
                throw new Exception('Authentication required; see VarnishAdminSocket::set_auth');
            }
            try {
                $challenge = substr($banner, 0, 32);
                $response = hash('sha256', $challenge . "\n" . $this->secret . $challenge . "\n");
                $banner = $this->command('auth ' . $response, $code);
            } catch (Exception) {
                throw new Exception('Authentication failed');
            }
        }

        if ($code !== 200) {
            throw new Exception(sprintf('Bad response from varnishadm on %s:%s', $this->host, $this->port));
        }

        return $banner;
    }

    /**
     * @param int reference for reply code
     * @return string
     * @throws Exception
     */
    private function read(&$code): string
    {
        $code = null;
        $len = 0;
        // get bytes until we have either a response code and message length or an end of file
        // code should be on first line, so we should get it in one chunk
        while (!feof($this->fp)) {
            $response = fgets($this->fp, 1024);
            if (!$response) {
                $meta = stream_get_meta_data($this->fp);
                if ($meta['timed_out']) {
                    throw new Exception(sprintf('Timed out reading from socket %s:%s', $this->host, $this->port));
                }
            }
            if (preg_match('/^(\d{3}) (\d+)/', $response, $r)) {
                $code = (int)$r[1];
                $len = (int)$r[2];
                break;
            }
        }
        if (is_null($code)) {
            throw new Exception('Failed to get numeric code in response');
        }
        $response = '';
        while (!feof($this->fp) && strlen($response) < $len) {
            $response .= fgets($this->fp, 1024);
        }
        return $response;
    }

    /**
     * Write a command to the socket with a trailing line break and get response straight away
     * @param string $cmd
     * @param int $code
     * @param int $ok
     * @return string
     * @throws Exception
     */
    public function command(string $cmd, int &$code, int $ok = 200): string
    {
        $cmd and $this->write($cmd);
        $this->write("\n");
        $response = $this->read($code);
        if ($code !== $ok) {
            $response = implode("\n > ", explode("\n", trim($response)));
            throw new Exception(sprintf("%s command responded %d:\n > %s", $cmd, $code, $response), $code);
        }
        return $response;
    }

    /**
     * Write data to the socket input stream
     * @param string
     * @return bool
     * @throws Exception
     */
    private function write(string $data): bool
    {
        $bytes = fputs($this->fp, $data);
        if ($bytes !== strlen($data)) {
            throw new Exception(sprintf('Failed to write to varnishadm on %s:%s', $this->host, $this->port));
        }
        return true;
    }

    /**
     * Graceful close, sends quit command
     * @return void
     */
    public function quit(): void
    {
        try {
            $code = 0;
            $this->command('quit', $code, 500);
        } catch (Exception) {
            // silent fail - force close of socket
        }
        $this->close();
    }

    /**
     * Brutal close, doesn't send quit command to varnishadm
     * @return void
     */
    public function close(): void
    {
        is_resource($this->fp) and fclose($this->fp);
        $this->fp = null;
    }

    /**
     * Shortcut to purge function
     * @see http://varnish-cache.org/wiki/Purging
     * @param string purge expression in form "<field> <operator> <arg> [&& <field> <oper> <arg>]..."
     * @return string
     * @throws Exception
     */
    public function purge($expr): string
    {
        $code = 0;
        return $this->command("ban" . ' ' . $expr, $code);
    }


    /**
     * Shortcut to purge.url function
     * @see http://varnish-cache.org/wiki/Purging
     * @param string url to purge
     * @return string
     * @throws Exception
     */
    public function purge_url($expr): string
    {
        $domain = parse_url($expr, PHP_URL_HOST);
        $path = parse_url($expr, PHP_URL_PATH);

        $code = 0;
        return $this->command('ban req.http.host == ' . $domain . ' && req.url ~ ' . $path . '/.*', $code);
    }


    /**
     * Shortcut to purge.list function
     * @return array
     * @throws Exception
     * @todo should we parse the response lines?
     */
    public function purge_list(): array
    {
        $code = 0;
        $response = $this->command('ban.list', $code);
        return explode("\n", trim($response));
    }

    /**
     * @return bool
     * @throws Exception
     */
    public function stop(): bool
    {
        if (!$this->status()) {
            trigger_error(sprintf('varnish host already stopped on %s:%s', $this->host, $this->port), E_USER_NOTICE);
            return true;
        }
        $code = 0;
        $this->command('stop', $code);
        return true;
    }

    /**
     * Test varnish child status
     * @return bool whether child is alive
     */
    public function status(): bool
    {
        try {
            $code = 0;
            $response = $this->command('status', $code);
            if (!preg_match('/Child in state (\w+)/', $response, $r)) {
                return false;
            }
            return $r[1] === 'running';
        } catch (Exception $Ex) {
            return false;
        }
    }

    /**
     * @return bool
     * @throws Exception
     */
    public function start(): bool
    {
        if ($this->status()) {
            trigger_error(sprintf('varnish host already started on %s:%s', $this->host, $this->port), E_USER_NOTICE);
            return true;
        }
        $code = 0;
        $this->command('start', $code);
        return true;
    }


}
