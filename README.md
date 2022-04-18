# MiTransport
Secure transport for Mirror

## Info
+ Using RSA for handshake phase (pre-generated)
+ Using AES for data exchange
+ Only encrypt message sent by reliable channel

## How it work

![mi_sequence](https://user-images.githubusercontent.com/9010717/163846736-6f06c70e-d1c3-4547-a575-6d37ace36a85.png)

0. Pre-generate the Rsa key pair
1. Client random AES key, iv (K1, IV1)
2. The client encrypts (K1, IV1) and sends it to the server using the rsa public key.
3. The server receives and decrypts ciphertext using rsa private key to get (K1, IV1).
4. The server generates a random Aes key, iv (K2, IV2), and uses the following formula to calculate the final key, iv (K, IV): K=K1 XOR K2, IV = IV1 XOR IV2.
5. (K2, IV2) is encrypted with (K1, IV1) and sent to the Client by the Server.
6. The client uses (K1, IV1) to decrypt ciphertext to get (K2, IV2).
7. The client calculate the final key, iv (K, IV) with same formula as server.
8. Client sends a Confirm message that is encrypted with (K, IV), and the client side handshake is complete.
9. The server confirms the message by decrypting it with (K, IV). The server side handshake has been completed.
10. With (K, IV), the client and server exchange data and encrypt and decrypt messages.

## How to use
0. Enable "Allow 'unsafe' code" in Player Settings  
1. Add MiTransport.cs to NetworkManager game object.  
2. Drag current transport to MiTransport innerTransport field.  
3. Replace transport on your NetworkManager to MiTransport.
4. Click Generate keypair button and save scene.

## Credits
Inspired by [Monke Transport][monke]

[monke]: <https://github.com/JesusLuvsYooh/monke> "Monke"
