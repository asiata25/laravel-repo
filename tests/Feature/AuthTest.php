<?php

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('registers a new user and returns an api token', function (): void {
    $response = $this->postJson('/api/register', [
        'name' => 'John Doe',
        'email' => 'john@example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ]);

    $response
        ->assertCreated()
        ->assertJsonStructure(['user' => ['id', 'name', 'email'], 'token'])
        ->assertJsonPath('user.email', 'john@example.com');

    $this->assertDatabaseHas('users', ['email' => 'john@example.com']);
});

it('rejects registration when the email is already taken', function (): void {
    $existing = User::factory()->create(['email' => 'john@example.com']);

    $response = $this->postJson('/api/register', [
        'name' => 'Jane Doe',
        'email' => $existing->email,
        'password' => 'password',
        'password_confirmation' => 'password',
    ]);

    $response->assertUnprocessable()->assertJsonValidationErrors('email');
});

it('logs a user in and returns an api token', function (): void {
    User::factory()->create(['email' => 'john@example.com', 'password' => 'password']);

    $response = $this->postJson('/api/login', [
        'email' => 'john@example.com',
        'password' => 'password',
    ]);

    $response
        ->assertOk()
        ->assertJsonStructure(['user' => ['id', 'name', 'email'], 'token'])
        ->assertJsonPath('user.email', 'john@example.com');
});

it('rejects login with invalid credentials', function (): void {
    User::factory()->create(['email' => 'john@example.com', 'password' => 'password']);

    $response = $this->postJson('/api/login', [
        'email' => 'john@example.com',
        'password' => 'wrong-password',
    ]);

    $response
        ->assertUnprocessable()
        ->assertJsonValidationErrors('email')
        ->assertJsonPath('errors.email.0', 'The provided credentials are incorrect.');
});

it('returns the authenticated user for a valid token', function (): void {
    $user = User::factory()->create();

    $response = $this->actingAs($user, 'sanctum')->getJson('/api/user');

    $response
        ->assertOk()
        ->assertJsonPath('email', $user->email);
});

it('rejects access to protected routes without a token', function (): void {
    $this->getJson('/api/user')->assertUnauthorized();
});

it('logs the user out and revokes the current token', function (): void {
    $user = User::factory()->create();
    $token = $user->createToken('test');
    $storedToken = $user->tokens()->first();

    $response = $this
        ->withHeader('Authorization', 'Bearer '.$token->plainTextToken)
        ->postJson('/api/logout');

    $response->assertOk()->assertJsonPath('message', 'Logged out successfully.');
    $this->assertDatabaseMissing('personal_access_tokens', ['id' => $storedToken->getKey()]);
});
