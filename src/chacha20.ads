--  Copyright (C) 2022 Mateus de Lima Oliveira

with Interfaces;
use Interfaces;

generic
   type Element is mod <>;
   type Element_Offset is range <>;
   type Data_Type is array (Element_Offset range <>) of Element;
package ChaCha20 is

   type ChaCha20 is private;

   procedure Encrypt_Bytes
     (X : in out ChaCha20;
      M : Data_Type;
      C : out Data_Type;
      Bytes : Unsigned_32);

   procedure Decrypt_Bytes
     (X :     in out ChaCha20;
      C :     Data_Type;
      M :     out Data_Type;
      Bytes : Unsigned_32);

   procedure Keystream_Bytes
     (X : in out ChaCha20;
      Stream : out Data_Type;
      Bytes : Unsigned_32);

   procedure Key_Setup
     (X       : in out ChaCha20;
      K       : Data_Type;
      K_Bits  : Unsigned_32;
      IV_Bits : Unsigned_32);

   procedure IV_Setup
     (X  : in out ChaCha20;
      IV : Data_Type);

   procedure Block_Counter_Setup
     (X : in out ChaCha20;
      Block_Counter : Unsigned_32);

   procedure Encrypt_Blocks
     (Context    : in out ChaCha20;
      Plaintext  : Data_Type;
      Ciphertext : out Data_Type;
      Blocks     : Unsigned_32);

   function Run_Tests return Boolean;

private

   type Input_Type is array (0 .. 15) of Unsigned_32;
   type Output_Type is array (0 .. 63) of Unsigned_32;

   type ChaCha20 is tagged record
      Input : Input_Type;
   end record;

end ChaCha20;
