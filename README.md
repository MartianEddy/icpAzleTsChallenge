# ICP-messaging
This project allows user to sign in as participants in a message group, send messages to other participants and get notified upon login for any unread messages.

## How to run the project
- Clone the repository
```
git clone git@github.com:boris-nikolov/ICP-azle-boilerplate.git
```
- Install dependencies
```
npm install
```
- Start DFX (omit `--clean` param on subsequent starts unless you'd like to start with clean data)
```
dfx start --background --clean
```
- Deploy canister
```
dfx deploy
```

## environment 
There is no native support for dfx on Windows. However, by installing the Windows Subsystem for Linux (WSL), you can run dfx also on a Windows system as described below.

 https://docs.microsoft.com/en-us/windows/wsl/install

 
Installing WSL 2
Follow Microsoft's instructions for installing the Windows Subsystem for Linux. Make sure you are running Windows 10 (version 2004 or higher) or Windows 11.

## installing dfx CLI

```
sh -ci "$(curl -fsSL https://internetcomputer.org/install.sh)"
```
## Use cases
- Create 2 participants (and capture the ID of the second user from the response)
```
dfx canister call message_board addParticipant '(record {"username"= "user1"; "password"= "password"})'
dfx canister call message_board addParticipant '(record {"username"= "user2"; "password"= "password"})'
```
- Login with the first user
```
dfx canister call message_board login '("user1", "password")'
```
You get a message saying:
```
(variant { Ok = "You have no new messages" })
```
- Create message to second user
```
dfx canister call message_board addMessage '(record {"title"= "Hello!"; "body"= "Welcome to our platform!"; "recipientId"= "ID OF RECIPIENT USER"})'
```

Replace the "recipientId" value with the ID of the second user that you've captured when creating (ex. `88641f68-d6a2-4cef-be2d-c5a16440e048`)
- Login with the second user
```
dfx canister call message_board login '("user2", "password")'
```
You get a message saying:
```
(variant { Ok = "You have 1 new messages" })
```
- To read the new message
```
dfx canister call message_board getMyMessages '()'
```
The result is something like:
```
(
  variant {
    Ok = vec {
      record {
        id = "1b5fcc98-58ce-46a5-908c-efc3f2a5e7cd";
        title = "Hello!";
        body = "Welcome to our platform!";
        createdAt = 1_693_407_647_726_476_205 : nat64;
        read = true;
        updatedAt = null;
        recipientId = "88641f68-d6a2-4cef-be2d-c5a16440e048";
        senderId = "a0a5674e-55d5-422b-8179-79acf6161124";
      };
    }
  },
)
```

