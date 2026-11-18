<?php

namespace PacoOrozco\OpenSSH\Tests;

use Illuminate\Support\Facades\Validator;
use PacoOrozco\OpenSSH\PrivateKey;
use PacoOrozco\OpenSSH\PublicKey;
use PacoOrozco\OpenSSH\Rules\PublicKeyRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

class PublicKeyValidationRuleTest extends TestCase
{
    public static function providesPublicKeyToTest(): \Generator
    {
        yield 'RSA public key' => [
            'filename' => 'id_rsa.pub',
        ];

        yield 'ed25519 public key' => [
            'filename' => 'id_ed25519.pub',
        ];
    }

    #[Test]
    #[DataProvider('providesPublicKeyToTest')]
    public function it_should_pass_when_key_is_public(
        string $filename,
    ): void {
        $validator = Validator::make(
            ['key' => PublicKey::fromFile($this->getStub($filename))],
            ['key' => new PublicKeyRule()]
        );

        $this->assertTrue($validator->passes());
    }

    #[Test]
    public function it_should_not_pass_when_key_is_not_public()
    {
        $validator = Validator::make(
            ['key' => PrivateKey::fromFile($this->getStub('id_rsa'))],
            ['key' => new PublicKeyRule()]
        );

        $this->assertFalse($validator->passes());
    }

    #[Test]
    public function it_should_not_pass_when_key_is_null()
    {
        $validator = Validator::make(
            ['key' => null],
            ['key' => new PublicKeyRule()]
        );

        $this->assertFalse($validator->passes());
    }
}
