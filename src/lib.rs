pub mod client;

pub use client::*;
// Master key
// Given by the client
// random
// 128 bits / 16 bytes
//
// Client random value
// for password processing function
// 128 bits / 16 bytes
//
// Salt
// Stays on the client
// SHA-256( “domain.com” || “Padding” || Client Random Value )
// Padding is a string of 'P's that combined with the 'domain' is equal to 200 char in lenght
//
// PPF
// iter = 100000
//
// Derived key
// client
// 256 bits / 32 bytes
// PBKDF2-HMAC-SHA-512( Password , Salt , Iterations , Length )
// the first 128 bits (from the left) are called derived encryption key
// the last 128 bits is the Derived Authentication key
//
// Encrypted Master key
// AES-ECB( Derived Encryption Key , Master Key )
//
// Hashed Auth Key
// SHA-256( Derived Authentication Key )
// It contains only the first 128 bits of the result
// add option to get full result
//
// Client payload
// First Name
// Last Name
// email
// Client random number
// Encrypyted master key
// Hashed auth key
