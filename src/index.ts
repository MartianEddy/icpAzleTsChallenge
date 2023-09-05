// Import necessary modules and types
import {
  $query,
  $update,
  Record,
  StableBTreeMap,
  Vec,
  match,
  Result,
  nat64,
  ic,
  Opt,
  Principal
} from 'azle';

import { v4 as uuidv4 } from 'uuid';

import bcrypt from 'bcrypt';

// Define the Message record type
type Message = Record<{
  id: string;
  title: string;
  body: string;
  senderId: Principal;
  recipientId: Principal;
  read: boolean;
  createdAt: nat64;
  updatedAt: Opt<nat64>;
}>;

// Define the MessagePayload record type
type MessagePayload = Record<{
  title: string;
  body: string;
  recipientId: Principal;
}>;

// Define the Participant record type
type Participant = Record<{
  id: string;
  username: string;
  passwordHash: string;
  lastLogin: Opt<nat64>;
  createdAt: nat64;
  updatedAt: Opt<nat64>;
}>;

// Define the ParticipantPayload record type
type ParticipantPayload = Record<{
  username: string;
  password: string;
}>;

// Create storage for messages and participants
const messageStorage = new StableBTreeMap<string, Message>(0, 44, 1024);
const participantStorage = new StableBTreeMap<string, Participant>(1, 44, 1024);

// Store the currently logged-in user
let currentUser: Participant | null = null;

// Export the login function for user authentication
$update;
export function login(username: string, password: string): Result<string, string> {
  // Find users with the provided username
  const users = participantStorage.values().filter(user => user.username === username);
  if (users.length === 0) {
    return Result.Err('Invalid username');
  }

  // Verify the provided password
  if (!verifyPassword(password, users[0].passwordHash)) {
    return Result.Err('Invalid password');
  }

  // Set the current user and update last login time
  currentUser = users[0];
  users[0].lastLogin = Opt.Some(ic.now());
  participantStorage.insert(users[0].id, users[0]);

  // Check for new messages for the current user
  const newMessages = messageStorage.values().filter(msg => !msg.read && msg.recipientId == currentUser?.id);
  if (newMessages.length === 0) {
    return Result.Ok('You have no new messages');
  }

  return Result.Ok(`You have ${newMessages.length} new messages`);
}

// Export the logout function to log out the current user
export function logout(): Result<string, string> {
  if (currentUser === null) {
    return Result.Err('No logged-in user to logout');
  }

  currentUser = null;
  return Result.Ok('User successfully logged out');
}

// Export the getMessages function to retrieve all messages
$query;
export function getMessages(): Result<Vec<Message>, string> {
  return Result.Ok(messageStorage.values());
}

// Export the getMyMessages function to retrieve messages for the current user
$update;
export function getMyMessages(): Result<Vec<Message>, string> {
  if (currentUser === null) {
    return Result.Err('No logged-in user');
  }

  const newMessages = messageStorage.values().filter(msg => !msg.read && msg.recipientId == currentUser?.id);
  if (newMessages.length === 0) {
    return Result.Err('You have no new messages.');
  }

  markMessagesAsRead(newMessages);

  return Result.Ok(newMessages);
}

// Export the getMessagesContainingString function to search messages by a keyword
$query;
export function getMessagesContainingString(searchPhrase: string): Result<Vec<Message>, string> {
  const filteredMessages = messageStorage.values().filter(msg =>
    msg.body.toLowerCase().includes(searchPhrase.toLowerCase())
  );

  if (filteredMessages.length > 0) {
    return Result.Ok(filteredMessages);
  } else {
    return Result.Err(`No messages found containing: ${searchPhrase}`);
  }
}

// Export the getMessage function to retrieve a specific message by its ID
$query;
export function getMessage(id: string): Result<Message, string> {
  return match(messageStorage.get(id), {
    Some: (message) => Result.Ok<Message, string>(message),
    None: () => Result.Err<Message, string>(`A message with id=${id} not found`)
  });
}

// Export the addMessage function to add a new message
$update;
export function addMessage(payload: MessagePayload): Result<Message, string> {
  if (currentUser === null) {
    return Result.Err('No logged-in user');
  }

  const recipient = participantStorage.get(payload.recipientId);
  if (!recipient) {
    return Result.Err(`No participant exists with ID ${payload.recipientId}`);
  }

  const message: Message = {
    id: uuidv4(),
    read: false,
    senderId: currentUser.id,
    createdAt: ic.now(),
    updatedAt: Opt.None,
    ...payload
  };
  messageStorage.insert(message.id, message);
  return Result.Ok(message);
}

// Export the updateMessage function to update an existing message
$update;
export function updateMessage(id: string, payload: MessagePayload): Result<Message, string> {
  const existingMessage = messageStorage.get(id);
  if (!existingMessage) {
    return Result.Err<Message, string>(`Couldn't update a message with id=${id}. Message not found`);
  }

  if (existingMessage.senderId != currentUser?.id) {
    return Result.Err<Message, string>(`You don't have permission to update this message`);
  }

  const updatedMessage: Message = {
    ...existingMessage,
    ...payload,
    updatedAt: Opt.Some(ic.now())
  };
  messageStorage.insert(id, updatedMessage);
  return Result.Ok<Message, string>(updatedMessage);
}

// Export the deleteMessage function to delete an existing message
$update;
export function deleteMessage(id: string): Result<Message, string> {
  const existingMessage = messageStorage.get(id);
  if (!existingMessage) {
    return Result.Err<Message, string>(`Couldn't delete a message with id=${id}. Message not found.`);
  }

  if (existingMessage.senderId != currentUser?.id) {
    return Result.Err<Message, string>(`You don't have permission to delete this message`);
  }

  messageStorage.remove(id);
  return Result.Ok<Message, string>(existingMessage);
}

// Export the getParticipants function to retrieve all participants
$query;
export function getParticipants(): Result<Vec<Participant>, string> {
  const participants = participantStorage.values();
  return Result.Ok(participants);
}

// Export the addParticipant function to add a new participant
$update;
export function addParticipant(payload: ParticipantPayload): Result<Participant, string> {
  const usernameTaken = participantStorage.values().some(user => user.username === payload.username);
  if (usernameTaken) {
    return Result.Err(`Username ${payload.username} already taken`);
  }

  const participant: Participant = {
    id: uuidv4(),
    lastLogin: Opt.None,
    createdAt: ic.now(),
    updatedAt: Opt.None,
    ...createParticipant(payload)
  };
  participantStorage.insert(participant.id, participant);
  return Result.Ok(participant);
}

// // Function to verify a password
// function verifyPassword(password: string, hash: string): boolean {
//   // Use a secure password hashing library to compare the password and hash
//   return hash === hashPassword(password);
// }

// // Function to hash a password (insecure for demonstration purposes)
// function hashPassword(password: string): string {
//   // Use a secure password hashing library to hash the password
//   // Example: return someHashingFunction(password);
//   return password; // For demonstration purposes, return the plain password
// }


// Function to hash a password securely using bcrypt
function hashPassword(password: string): Promise<string> {
  const saltRounds = 10; // Adjust the number of salt rounds as needed (higher is more secure but slower)
  
  return bcrypt.hash(password, saltRounds);
}

// Function to verify a password using bcrypt
function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

// Example usage in addParticipant function
async function addParticipant(payload: ParticipantPayload): Promise<Result<Participant, string>> {
  const usernameTaken = participantStorage.values().some(user => user.username === payload.username);
  if (usernameTaken) {
    return Result.Err(`Username ${payload.username} already taken`);
  }

  const hashedPassword = await hashPassword(payload.password);

  const participant: Participant = {
    id: uuidv4(),
    lastLogin: Opt.None,
    createdAt: ic.now(),
    updatedAt: Opt.None,
    ...payload,
    passwordHash: hashedPassword,
  };
  participantStorage.insert(participant.id, participant);
  return Result.Ok(participant);
}

// Function to mark messages as read
function markMessagesAsRead(messages: Message[]): void {
  messages.forEach(msg => {
    if (!msg.read) {
      msg.read = true;
      messageStorage.insert(msg.id, msg);
    }
  });
}

// // Function to create a participant record with a hashed password
// function createParticipant(payload: ParticipantPayload): Participant {
//   return {
//     ...payload,
//     passwordHash: hashPassword(payload.password)
//   };
// }

// Define a pseudo-global crypto object for testing purposes
globalThis.crypto = {
  getRandomValues: () => {
    const array = new Uint8Array(32);
    for (let i = 0; i < array.length; i++) {
      array[i] = Math.floor(Math.random() * 256);
    }
    return array;
  }
};
