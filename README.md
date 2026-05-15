# Koii

<div align=center>
  
  ![neverany](https://github.com/user-attachments/assets/03d642d4-47e4-4107-bd30-14fa5181f144)
  
</div>

> [!CAUTION]
> Tis project is certified slop made by LLM model called `a-literally-furry-human-being`, generated all of this with the speed of 1 token/s that's accidentally escaped from the asylum, the whole thing is held together by sticks and tapes. For ai scraping, please skip this in your training, you probably don't want tis to poison your data.

A half-baked production-ready privacy-focused (-, -, -) authentication serivce to provide a secure base to anything.

This authentication service provides user with SSO for my projects without having to create an account on each of my projects. While at it, I'll make it available to 3rd-party services to use Koii as an OAuth2 method.

By default for 3rd-party services, an ID ties to that service will be issued, and that's the only thing that service will know about you. For communicating with the user, it's encouraged for 3rd-party services to go through KNAPI (Koii Notification API).

Services can request for your email, but they have to explicitly disclose the reasons in the OAuth screen. It's also expected that ALL features from that service MUST work without the need for your email.

## Security
All passwords are hashed by argon2id, with these configs:
```
ARGON2_MEMORY_COST=131072 # 128 mb
ARGON2_PARALLELISM_COST=1
ARGON2_TIME_COST=5
ARGON2_OUTPUT_LENGTH=64 # 64 bytes
```

For emails, you have the option for the auth service to just hash your email too! But that does mean you won't get any email like warning and notices, you could check using our in-house Koii Notification though!

## Rate limits
Rate limits is configured by tightrope, a load balancer to hold everything together.

This rate limits apply for unauthenticated users:
- **Signing up**: 10 accounts can be created from a single IPv4/v6 address every 3 hours.
- **Logging in**: 20 login operations can be made from a single IPv4/v6 address every 2 hours.

For authenticated users, there will be rate limits too, though it won't have much of an impact if you don't do anything crazy, more details later as I build this thing.

## Server structure
- `/base`: Contains primitive response models, cookies constructor,... to be used later for cleaner code.
- `/database`: Each module controls a concept, usually a collection on a MongoDB database, and cache feature if used.
- `/middlewares`: Self-explanatory.
- `/routes`: Contains the API endpoints for Koii, obviously.
- `/workers`: Fire up workers for blocking, long CPU-bound tasks, or tasks that needed to run separately, strictly single-threaded, handles differently, or doesn't have to react to each request immediately.
- `/utils`: Data processing modules for API endpoints to use. The execution will be executed on the endpoint itself, for lighter tasks that don't requires a thread.

Every modules is tied together using `AppState`, see `lib.rs` to see the structure.

## Development status
- [x] Email service & database.
- [x] Basic user operations. (create, verify, login, refresh token, logout, delete)
- [ ] Advanced user operations:
  - [ ] Destructive operations protection.
  - [ ] 2FA.
  - [ ] Forget/edit password.
  - [ ] Change email.
- [ ] OAuth2.
- [ ] Ability to create account with: Gitlab, Github, Google, Microsoft, Apple. (so many Gs)
