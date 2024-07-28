<?php

declare(strict_types=1);

/**
 * This file is part of Shield OAuth.
 *
 * (c) Datamweb <pooya_parsa_dadashi@yahoo.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

use CodeIgniter\CodingStandard\CodeIgniter4;
use Nexus\CsConfig\Factory;
use PhpCsFixer\Finder;

$finder = Finder::create()
    ->files()
    ->in([
        __DIR__ . '/src/',
        // __DIR__ . '/tests/',
    ])
    ->exclude('build')
    ->append([
        __FILE__,
        __DIR__ . '/rector.php',
    ]);

$overrides = [
    'declare_strict_types' => true,
    'void_return'          => true,
    'modernize_strpos'     => false,
];

$options = [
    'finder'    => $finder,
    'cacheFile' => '.php-cs-fixer.cache',
];

return Factory::create(new CodeIgniter4(), $overrides, $options)->forLibrary(
    'Shield OAuth',
    'Datamweb',
    'pooya_parsa_dadashi@yahoo.com'
);
