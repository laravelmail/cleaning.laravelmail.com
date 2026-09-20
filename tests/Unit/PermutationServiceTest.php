<?php
namespace Tests\Unit;use App\Services\PermutationService;use PHPUnit\Framework\TestCase;
final class PermutationServiceTest extends TestCase {public function test_it_matches_core_permutation_shapes_and_deduplicates():void{$emails=(new PermutationService())->generate('John','Doe','Example.com','Johnny');$this->assertContains('john.doe@example.com',$emails);$this->assertContains('jdoe@example.com',$emails);$this->assertContains('johnny@example.com',$emails);$this->assertSame($emails,array_values(array_unique($emails)));}}
