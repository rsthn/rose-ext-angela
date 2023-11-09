<?php

use Rose\Errors\Error;
use Rose\IO\Directory;
use Rose\IO\Path;
use Rose\IO\File;
use Rose\Map;
use Rose\Text;
use Rose\Math;
use Rose\Expr;
use Rose\Arry;

class Angela
{
    private static $consts = null;
    private static $ctx = null;

    private $input;
    private $out;
    private $p;
    private $q;
    private $kw;
    private $level;
    private $kl;
    private $ki;

    public static function uint8 ($value) {
        return ($value + 0x100) & 0xFF;
    }

    public static function uint16 ($value) {
        return ($value + 0x10000) & 0xFFFF;
    }

    public static function int8 ($value) {
        return ($value & 0xFF) - (($value & 0xFF) < 0x80 ? 0 : 0x100);
    }

    public static function int16 ($value) {
        return ($value & 0xFFFF) - (($value & 0xFFFF) < 0x8000 ? 0 : 0x10000);
    }

    private static function rol ($v, $n, $m)
    {
        $v &= (1 << $m) - 1;
        return ((($v << $n) | (((($v >> ($m - $n))) & ((1 << $n) - 1) )))) & ((1 << $m) - 1);
    }

    private static function ror ($v, $n, $m)
    {
        return self::rol($v, $m - $n, $m);
    }

    public function __construct ()
    {
        if (self::$consts === null)
            self::$consts = [ 67,53,419,709,373,101,401,761,997,739,641,313,61,83,59,769,1129,2969,4937,5743,7237,6571,8167,8713,8933,5179,3673,3727,3083,4817,4523,4507 ];

        $this->input = [ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 ];
        $this->out = [ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 ];
        $this->p = [ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 ];
        $this->q = [ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 ];
    }

    /**
     * Initializes the context with the specified secret.
     */
    public function init ($secret)
    {
        $this->level = $this->ki = 0;
        $this->kw = Text::split('', $secret)->map(function($c) { return ord($c); });
        $this->kl = $this->kw->length();
        $this->kw = $this->kw->__nativeArray;

        for ($i = 0; $i < 32; $i++) {
            $this->p[$i] = self::$consts[$i];
            $this->q[$i] = self::$consts[32 - $i - 1];
        }

        $j = 42279;
        if ($this->kl != 0) {
            for ($i = $j = 0; $i < $this->kl; $i++)
                $j += 3 * $this->kw[$i];
        }

        $sumH = ($j >> 8) & 255;
        $sumL = $j & 255;
        for ($i = 0; $i < 32; $i++) {
            $this->p[$i & 31] = self::ror($this->p[$i] + $sumH, $sumH & 5, 16) - $this->p[($i + 1) & 31];
            $this->q[$i & 31] = self::rol($this->q[$i] + $this->q[($i + 1) & 31], $sumL & 3, 16) - $sumL;
            $j = $this->p[$i] & $this->q[$i];
            $sumH += $j & 0xF0;
            $sumL -= $j & 0x0F;
        }
    }

    public function isInputFull() {
        return $this->level == 32;
    }

    public function isInputEmpty() {
        return $this->level == 0;
    }

    public function inputSpace() {
        return 32 - $this->level;
    }

    public function getOutput() {
        return $this->out;
    }

    public function getInput() {
        return $this->input;
    }

    public static function getOutputSize($n) {
        return (($n + 32) - 1) & -32;
    }

    public static function getBottomBytes ($n) {
        return ($n & 31) != 0 ? ($n & 31) : 32;
    }

    public function encryptBlock()
    {
        if ($this->kl != 0) {
            for ($i = 0; $i < 32; $i++) {
                $this->q[$i] = self::rol($this->q[$i] + $this->kw[$this->ki], $this->kw[$this->ki] & 3, 16);
                $this->ki = ++$this->ki % $this->kl;
            }
        }

        for ($i = 0; $i < 32; $i++)
            $this->q[$i] = self::ror($this->q[$i], $this->q[$i] & 5, 16) ^ self::rol($this->p[$i], $this->p[$i] & 7, 16);

        for ($i = 0; $i < 32; $i++) {
            $k = $this->input[$i];
            $k2 = self::rol($k, 4, 8) ^ $this->p[$i];
            $k2 = $k2 + self::ror($this->q[(32 - $i) - 1], $this->p[$i] & 3, 8);
            $k &= 255;
            $k2 &= 255;
            $this->p[$i] ^= $k + $k2;
            $this->out[$i] = $k2;
        }

        $this->level = 0;
        return $this->out;
    }

    public function decryptBlock()
    {
        if ($this->kl != 0)
        {
            for ($i = 0; $i < 32; $i++) {
                $this->q[$i] = self::rol($this->q[$i] + $this->kw[$this->ki], $this->kw[$this->ki] & 3, 16);
                $this->ki = ++$this->ki % $this->kl;
            }
        }

        for ($i = 0; $i < 32; $i++)
            $this->q[$i] = self::ror($this->q[$i], $this->q[$i] & 5, 16) ^ self::rol($this->p[$i], $this->p[$i] & 7, 16);

        for ($i = 0; $i < 32; $i++) {
            $k2 = $this->input[$i];
            $k = $k2 - self::ror($this->q[32 - $i - 1], $this->p[$i] & 3, 8);
            $k = self::ror($k ^ $this->p[$i], 4, 8);
            $k &= 255;
            $k2 &= 255;
            $this->p[$i] ^= $k + $k2;
            $this->out[$i] = $k;
        }

        $this->level = 0;
        return $this->out;
    }

    public function feed ($value)
    {
        if ($this->level == 32)
            return false;

        $this->input[$this->level] = ($value + 256) & 255;
        $this->level++;
        return true;
    }

    /**
     * Encrypts the given data with the given secret.
     */
    public static function encrypt ($secret, $data, $randomSalt=false)
    {
        if (self::$ctx === null)
            self::$ctx = new Angela();

        $b_dest = '';

        self::$ctx->init($secret);
        $length = Text::length($data);
        $s = $randomSalt ? Math::rand() : 33;

        self::$ctx->feed($s);

        for ($i = 0; $i < $length; $i++) {
            if (self::$ctx->feed(ord($data[$i])))
                continue;

            self::$ctx->encryptBlock();
            $z = self::$ctx->getOutput();
            for ($j = 0; $j < 32; $j++) $b_dest .= chr($z[$j]);
            $i--;
        }

        if (!self::$ctx->feed($s)) {
            self::$ctx->encryptBlock();
            $z = self::$ctx->getOutput();
            for ($j = 0; $j < 32; $j++) $b_dest .= chr($z[$j]);
            self::$ctx->feed($s);
        }

        if (self::$ctx->inputSpace() == 0) {
            self::$ctx->encryptBlock();
            $z = self::$ctx->getOutput();
            for ($j = 0; $j < 32; $j++) $b_dest .= chr($z[$j]);
        }

        $s = 0;
        while (self::$ctx->inputSpace() != 1) {
            self::$ctx->feed(0);
            $s++;
        };

        self::$ctx->feed($s);
        if (!self::$ctx->isInputEmpty()) {
            self::$ctx->encryptBlock();
            $z = self::$ctx->getOutput();
            for ($j = 0; $j < 32; $j++) $b_dest .= chr($z[$j]);
        }

        return $b_dest;
    }

    /**
     * Decrypts the given data with the given key.
     */
    public static function decrypt ($secret, $data)
    {
        if (self::$ctx === null)
            self::$ctx = new Angela();

        $b_dest = '';

        self::$ctx->init($secret);
        $length = Text::length($data);

        for ($i = 0; $i < $length; $i++)
        {
            if (self::$ctx->feed(ord($data[$i])))
                continue;

            $z = self::$ctx->decryptBlock();
            for ($j = 0; $j < 32; $j++) $b_dest .= chr($z[$j]);
            $i--;
        }

        if (!self::$ctx->isInputEmpty()) {
            $z = self::$ctx->decryptBlock();
            for ($j = 0; $j < 32; $j++) $b_dest .= chr($z[$j]);
        }

        $s = ord(Text::substring($b_dest, -1));
        if ($s < 0 || $s > 32) return null;

        $b_dest = Text::substring($b_dest, 0, -$s - 1);
        if ($b_dest[0] != $b_dest[Text::length($b_dest) - 1]) return null;

        return Text::substring($b_dest, 1, -1);
    }
};

/**
 * Encrypts the specified text using Angela.
 * (eax::encrypt <key> <plainText>)
 */
Expr::register('eax::encrypt', function ($args) {
    return Angela::encrypt($args->get(1), $args->get(2));
});

/**
 * Decrypts the specified cypher using Angela.
 * (eax::decrypt <key> <cypherText>)
 */
Expr::register('eax::decrypt', function ($args) {
    return Angela::decrypt($args->get(1), $args->get(2));
});
