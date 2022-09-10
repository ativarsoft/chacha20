--  Copyright (C) 2022 Mateus de Lima Oliveira

package body ChaCha20 is
   --
   --  Utility function
   --

   procedure U32TO8_LITTLE
     (Stream   : out Data_Type;
      Value : Unsigned_32)
   is
      Bytes : Data_Type (1 .. 4);
   begin
      Bytes (1) := Element (Shift_Right (Value, 0 * 8) and 16#FF#);
      Bytes (2) := Element (Shift_Right (Value, 1 * 8) and 16#FF#);
      Bytes (3) := Element (Shift_Right (Value, 2 * 8) and 16#FF#);
      Bytes (4) := Element (Shift_Right (Value, 3 * 8) and 16#FF#);
      Stream := Bytes (1 .. 4);
   end U32TO8_LITTLE;

   function U8TO32_LITTLE
     (Stream : Data_Type)
      return Unsigned_32
   is
      Bytes : Data_Type (1 .. 4);
      Value : Unsigned_32 := 0;
   begin
      Bytes (1 .. 4) := Stream;
      Value := Value or Shift_Left (Unsigned_32 (Bytes (1)), 0 * 8);
      Value := Value or Shift_Left (Unsigned_32 (Bytes (2)), 1 * 8);
      Value := Value or Shift_Left (Unsigned_32 (Bytes (3)), 2 * 8);
      Value := Value or Shift_Left (Unsigned_32 (Bytes (4)), 3 * 8);
      return Value;
   end U8TO32_LITTLE;

   --
   --  Encryption / Decryption
   --

   procedure QUARTERROUND
     (X : in out Input_Type;
      A : Natural;
      B : Natural;
      C : Natural;
      D : Natural)
   is
   begin
      X (A) := X (A) + X (B); X (D) := Rotate_Left (X (D) xor X (A), 16);
      X (C) := X (C) + X (D); X (B) := Rotate_Left (X (B) xor X (C), 12);
      X (A) := X (A) + X (B); X (D) := Rotate_Left (X (D) xor X (A), 8);
      X (C) := X (C) + X (D); X (B) := Rotate_Left (X (B) xor X (C), 7);
   end QUARTERROUND;

   procedure Salsa20_Word_To_Byte
     (Output : out Data_Type;
      Input : Input_Type)
   is
      X : Input_Type;
      I : Natural := 0;
      First, Last : Element_Offset;
   begin
      X := Input;
      while I < 10 loop -- !!!
         --  "column" round
         QUARTERROUND (X, 0, 4, 8,  12);
         QUARTERROUND (X, 1, 5, 9,  13);
         QUARTERROUND (X, 2, 6, 10, 14);
         QUARTERROUND (X, 3, 7, 11, 15);
         --  "diagonal" round
         QUARTERROUND (X, 0, 5, 10, 15);
         QUARTERROUND (X, 1, 6, 11, 12);
         QUARTERROUND (X, 2, 7,  8, 13);
         QUARTERROUND (X, 3, 4,  9, 14);
         I := I + 1;
      end loop;
      for I in Input'Range loop
         X (I) := X (I) + Input (I);
      end loop;
      for I in Input'Range loop
         First := Output'First + Element_Offset (4 * I);
         Last := First + 3;
         U32TO8_LITTLE (Output (First .. Last), X (I));
      end loop;
   end Salsa20_Word_To_Byte;

   procedure Encrypt_Bytes
     (X     : in out ChaCha20;
      M     : Data_Type;
      C     : out Data_Type;
      Bytes : Unsigned_32)
   is
      Output : Data_Type (0 .. 63) := (others => 0);
      C_Index : Element_Offset := C'First;
      M_Index : Element_Offset := M'First;
      Remaining_Bytes : Unsigned_32 := Bytes;
   begin
      if Bytes = 0 then
         return;
      end if;
      loop
         Salsa20_Word_To_Byte (Output, X.Input);
         X.Input (12) := X.Input (12) + 1;
         if X.Input (12) = 0 then
            X.Input (13) := X.Input (13) + 1;
            --  stopping at 2^70 bytes per nonce is user's responsibility
         end if;
         if Remaining_Bytes <= 64 then
            for J in 0 .. Element_Offset (Remaining_Bytes) - 1 loop
               C (J + C_Index) := M (J + M_Index) xor Output (J);
            end loop;
            return;
         end if;
         for J in 0 .. Element_Offset'(63) loop
            C (J + C_Index) := M (J + M_Index) xor Output (J);
         end loop;
         Remaining_Bytes := Remaining_Bytes - 64;
         C_Index := C_Index + 64;
         M_Index := M_Index + 64;
      end loop;
   end Encrypt_Bytes;

   procedure Decrypt_Bytes
     (X : in out ChaCha20;
      C : Data_Type;
      M : out Data_Type;
      Bytes : Unsigned_32)
   is
   begin
      Encrypt_Bytes
        (X => X,
         M => C,
         C => M,
         Bytes => Bytes);
   end Decrypt_Bytes;

   procedure Keystream_Bytes
     (X : in out ChaCha20;
      Stream : out Data_Type;
      Bytes : Unsigned_32)
   is
   begin
      for I in 0 .. Element_Offset (Bytes) - 1 loop
         Stream (I) := 0;
      end loop;
      Encrypt_Bytes (X, Stream, Stream, Bytes);
   end Keystream_Bytes;

   --
   --  Key
   --

   function String_To_Key (S : String) return Data_Type is
      Key : Data_Type (0 .. S'Length - 1);
      Key_Index : Element_Offset;
   begin
      for I in 0 .. S'Length - 1 loop
         Key_Index := Element_Offset (I);
         Key (Key_Index) := Element (Character'Pos (S (S'First + I)));
      end loop;
      return Key;
   end String_To_Key;

   Sigma : aliased constant Data_Type := String_To_Key ("expand 32-byte k");
   Tau : aliased constant Data_Type := String_To_Key ("expand 16-byte k");

   procedure Key_Setup
     (X       : in out ChaCha20;
      K       : Data_Type;
      K_Bits  : Unsigned_32;
      IV_Bits : Unsigned_32)
   is
      Constants : access constant Data_Type;
      K_Index : Element_Offset := K'First;
      K_Slice : Data_Type (0 .. 3);
   begin
      K_Slice := K (K_Index + 0 .. K_Index + 0 + 3);
      X.Input (4) := U8TO32_LITTLE (K_Slice);
      K_Slice := K (K_Index + 4 .. K_Index + 4 + 3);
      X.Input (5) := U8TO32_LITTLE (K_Slice);
      K_Slice := K (K_Index + 8 .. K_Index + 8 + 3);
      X.Input (6) := U8TO32_LITTLE (K_Slice);
      K_Slice := K (K_Index + 12 .. K_Index + 12 + 3);
      X.Input (7) := U8TO32_LITTLE (K_Slice);
      if K_Bits = 256 then -- Recommended.
         K_Index := K_Index + 16;
         Constants := Sigma'Access;
      else -- K_Bits = 128
         Constants := Tau'Access;
      end if;
      K_Slice := K (K_Index + 0 .. K_Index + 0 + 3);
      X.Input (8) := U8TO32_LITTLE (K_Slice);
      K_Slice := K (K_Index + 4 .. K_Index + 4 + 3);
      X.Input (9) := U8TO32_LITTLE (K_Slice);
      K_Slice := K (K_Index + 8 .. K_Index + 8 + 3);
      X.Input (10) := U8TO32_LITTLE (K_Slice);
      K_Slice := K (K_Index + 12 .. K_Index + 12 + 3);
      X.Input (11) := U8TO32_LITTLE (K_Slice);
      X.Input (0) := U8TO32_LITTLE (Constants (0 .. 3));
      X.Input (1) := U8TO32_LITTLE (Constants (4 .. 4 + 3));
      X.Input (2) := U8TO32_LITTLE (Constants (8 .. 8 + 3));
      X.Input (3) := U8TO32_LITTLE (Constants (12 .. 12 + 3));
   end Key_Setup;

   procedure IV_Setup
     (X  : in out ChaCha20;
      IV : Data_Type)
   is
      IV_Slice : constant Data_Type (0 .. 11) := IV;
   begin
      X.Input (13) := U8TO32_LITTLE (IV_Slice (0 .. 3));
      X.Input (14) := U8TO32_LITTLE (IV_Slice (4 .. 7));
      X.Input (15) := U8TO32_LITTLE (IV_Slice (8 .. 11));
   end IV_Setup;

   procedure Block_Counter_Setup
     (X : in out ChaCha20;
      Block_Counter : Unsigned_32)
   is
   begin
      --  "Word 12 is a block counter. Since each block is 64-byte, a 32-bit
      --   word is enough for 256 gigabytes of data."
      X.Input (12) := Block_Counter;
   end Block_Counter_Setup;

   BLOCK_LENGTH : constant := 64;

   procedure Encrypt_Blocks
     (Context    : in out ChaCha20;
      Plaintext  : Data_Type;
      Ciphertext : out Data_Type;
      Blocks     : Unsigned_32)
   is
   begin
      Encrypt_Bytes (Context, Plaintext, Ciphertext,
                     (Blocks) * BLOCK_LENGTH);
   end Encrypt_Blocks;

   function Test_Quarter_Round return Boolean
   is
      Input : Input_Type :=
        (16#879531e0#, 16#c5ecf37d#, 16#516461b1#, 16#c9a62f8a#,
         16#44c20ef3#, 16#3390af7f#, 16#d9fc690b#, 16#2a5f714c#,
         16#53372767#, 16#b00a5631#, 16#974c541a#, 16#359e9963#,
         16#5c971061#, 16#3d631689#, 16#2098d9d6#, 16#91dbd320#);
   begin
      QUARTERROUND (Input, 2, 7, 8, 13);
      return True; -- TODO: check output.
   end Test_Quarter_Round;

   function Test_1 return Boolean
   is
      X : ChaCha20 := ChaCha20'(Input => (others => 0));
      Key : constant Data_Type (0 .. 32 - 1) := (others => 0);
      IV : constant Data_Type (0 .. 12 - 1) := (others => 0);
      Block_Counter : constant Unsigned_32 := 0;
      M : constant Data_Type (0 .. 64 - 1) := (others => 0);
      C : Data_Type (0 .. M'Length - 1) := (others => 0);

      A : constant Input_Type :=
        (16#61707865#, 16#3320646e#, 16#79622d32#, 16#6b206574#, others => 0);
      B : constant Data_Type :=
        (16#76#, 16#b8#, 16#e0#, 16#ad#, 16#a0#, 16#f1#, 16#3d#, 16#90#,
         16#40#, 16#5d#, 16#6a#, 16#e5#, 16#53#, 16#86#, 16#bd#, 16#28#,
         16#bd#, 16#d2#, 16#19#, 16#b8#, 16#a0#, 16#8d#, 16#ed#, 16#1a#,
         16#a8#, 16#36#, 16#ef#, 16#cc#, 16#8b#, 16#77#, 16#0d#, 16#c7#,
         16#da#, 16#41#, 16#59#, 16#7c#, 16#51#, 16#57#, 16#48#, 16#8d#,
         16#77#, 16#24#, 16#e0#, 16#3f#, 16#b8#, 16#d8#, 16#4a#, 16#37#,
         16#6a#, 16#43#, 16#b8#, 16#f4#, 16#15#, 16#18#, 16#a1#, 16#1c#,
         16#c3#, 16#87#, 16#b6#, 16#69#, 16#b2#, 16#ee#, 16#65#, 16#86#);
   begin
      Key_Setup (X, Key, 256, 0);
      IV_Setup (X, IV);
      Block_Counter_Setup (X, Block_Counter);

      --  The first four words (0-3) are constants:
      --  0x61707865, 0x3320646e, 0x79622d32, 0x6b206574.
      if X.Input /= A then
         return False;
      end if;

      Encrypt_Bytes (X, M, C, M'Length);

      if C /= B then
         return False;
      end if;

      return True;
   end Test_1;

   function Test_2 return Boolean
   is
      X : ChaCha20 := ChaCha20'(Input => (others => 0));
      Key : constant Data_Type (0 .. 32 - 1) := (31 => 1, others => 0);
      IV : constant Data_Type (0 .. 12 - 1) :=
        (16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#02#);
      Block_Counter : constant Unsigned_32 := 1;
      M : constant Data_Type :=
        (16#41#, 16#6e#, 16#79#, 16#20#, 16#73#, 16#75#, 16#62#, 16#6d#,
         16#69#, 16#73#, 16#73#, 16#69#, 16#6f#, 16#6e#, 16#20#, 16#74#,
         16#6f#, 16#20#, 16#74#, 16#68#, 16#65#, 16#20#, 16#49#, 16#45#,
         16#54#, 16#46#, 16#20#, 16#69#, 16#6e#, 16#74#, 16#65#, 16#6e#,
         16#64#, 16#65#, 16#64#, 16#20#, 16#62#, 16#79#, 16#20#, 16#74#,
         16#68#, 16#65#, 16#20#, 16#43#, 16#6f#, 16#6e#, 16#74#, 16#72#,
         16#69#, 16#62#, 16#75#, 16#74#, 16#6f#, 16#72#, 16#20#, 16#66#,
         16#6f#, 16#72#, 16#20#, 16#70#, 16#75#, 16#62#, 16#6c#, 16#69#,
         16#63#, 16#61#, 16#74#, 16#69#, 16#6f#, 16#6e#, 16#20#, 16#61#,
         16#73#, 16#20#, 16#61#, 16#6c#, 16#6c#, 16#20#, 16#6f#, 16#72#,
         16#20#, 16#70#, 16#61#, 16#72#, 16#74#, 16#20#, 16#6f#, 16#66#,
         16#20#, 16#61#, 16#6e#, 16#20#, 16#49#, 16#45#, 16#54#, 16#46#,
         16#20#, 16#49#, 16#6e#, 16#74#, 16#65#, 16#72#, 16#6e#, 16#65#,
         16#74#, 16#2d#, 16#44#, 16#72#, 16#61#, 16#66#, 16#74#, 16#20#,
         16#6f#, 16#72#, 16#20#, 16#52#, 16#46#, 16#43#, 16#20#, 16#61#,
         16#6e#, 16#64#, 16#20#, 16#61#, 16#6e#, 16#79#, 16#20#, 16#73#,
         16#74#, 16#61#, 16#74#, 16#65#, 16#6d#, 16#65#, 16#6e#, 16#74#,
         16#20#, 16#6d#, 16#61#, 16#64#, 16#65#, 16#20#, 16#77#, 16#69#,
         16#74#, 16#68#, 16#69#, 16#6e#, 16#20#, 16#74#, 16#68#, 16#65#,
         16#20#, 16#63#, 16#6f#, 16#6e#, 16#74#, 16#65#, 16#78#, 16#74#,
         16#20#, 16#6f#, 16#66#, 16#20#, 16#61#, 16#6e#, 16#20#, 16#49#,
         16#45#, 16#54#, 16#46#, 16#20#, 16#61#, 16#63#, 16#74#, 16#69#,
         16#76#, 16#69#, 16#74#, 16#79#, 16#20#, 16#69#, 16#73#, 16#20#,
         16#63#, 16#6f#, 16#6e#, 16#73#, 16#69#, 16#64#, 16#65#, 16#72#,
         16#65#, 16#64#, 16#20#, 16#61#, 16#6e#, 16#20#, 16#22#, 16#49#,
         16#45#, 16#54#, 16#46#, 16#20#, 16#43#, 16#6f#, 16#6e#, 16#74#,
         16#72#, 16#69#, 16#62#, 16#75#, 16#74#, 16#69#, 16#6f#, 16#6e#,
         16#22#, 16#2e#, 16#20#, 16#53#, 16#75#, 16#63#, 16#68#, 16#20#,
         16#73#, 16#74#, 16#61#, 16#74#, 16#65#, 16#6d#, 16#65#, 16#6e#,
         16#74#, 16#73#, 16#20#, 16#69#, 16#6e#, 16#63#, 16#6c#, 16#75#,
         16#64#, 16#65#, 16#20#, 16#6f#, 16#72#, 16#61#, 16#6c#, 16#20#,
         16#73#, 16#74#, 16#61#, 16#74#, 16#65#, 16#6d#, 16#65#, 16#6e#,
         16#74#, 16#73#, 16#20#, 16#69#, 16#6e#, 16#20#, 16#49#, 16#45#,
         16#54#, 16#46#, 16#20#, 16#73#, 16#65#, 16#73#, 16#73#, 16#69#,
         16#6f#, 16#6e#, 16#73#, 16#2c#, 16#20#, 16#61#, 16#73#, 16#20#,
         16#77#, 16#65#, 16#6c#, 16#6c#, 16#20#, 16#61#, 16#73#, 16#20#,
         16#77#, 16#72#, 16#69#, 16#74#, 16#74#, 16#65#, 16#6e#, 16#20#,
         16#61#, 16#6e#, 16#64#, 16#20#, 16#65#, 16#6c#, 16#65#, 16#63#,
         16#74#, 16#72#, 16#6f#, 16#6e#, 16#69#, 16#63#, 16#20#, 16#63#,
         16#6f#, 16#6d#, 16#6d#, 16#75#, 16#6e#, 16#69#, 16#63#, 16#61#,
         16#74#, 16#69#, 16#6f#, 16#6e#, 16#73#, 16#20#, 16#6d#, 16#61#,
         16#64#, 16#65#, 16#20#, 16#61#, 16#74#, 16#20#, 16#61#, 16#6e#,
         16#79#, 16#20#, 16#74#, 16#69#, 16#6d#, 16#65#, 16#20#, 16#6f#,
         16#72#, 16#20#, 16#70#, 16#6c#, 16#61#, 16#63#, 16#65#, 16#2c#,
         16#20#, 16#77#, 16#68#, 16#69#, 16#63#, 16#68#, 16#20#, 16#61#,
         16#72#, 16#65#, 16#20#, 16#61#, 16#64#, 16#64#, 16#72#, 16#65#,
         16#73#, 16#73#, 16#65#, 16#64#, 16#20#, 16#74#, 16#6f#);
      C : Data_Type (0 .. M'Length - 1) := (others => 0);

      Ciphertext : constant Data_Type :=
        (16#a3#, 16#fb#, 16#f0#, 16#7d#, 16#f3#, 16#fa#, 16#2f#, 16#de#,
         16#4f#, 16#37#, 16#6c#, 16#a2#, 16#3e#, 16#82#, 16#73#, 16#70#,
         16#41#, 16#60#, 16#5d#, 16#9f#, 16#4f#, 16#4f#, 16#57#, 16#bd#,
         16#8c#, 16#ff#, 16#2c#, 16#1d#, 16#4b#, 16#79#, 16#55#, 16#ec#,
         16#2a#, 16#97#, 16#94#, 16#8b#, 16#d3#, 16#72#, 16#29#, 16#15#,
         16#c8#, 16#f3#, 16#d3#, 16#37#, 16#f7#, 16#d3#, 16#70#, 16#05#,
         16#0e#, 16#9e#, 16#96#, 16#d6#, 16#47#, 16#b7#, 16#c3#, 16#9f#,
         16#56#, 16#e0#, 16#31#, 16#ca#, 16#5e#, 16#b6#, 16#25#, 16#0d#,
         16#40#, 16#42#, 16#e0#, 16#27#, 16#85#, 16#ec#, 16#ec#, 16#fa#,
         16#4b#, 16#4b#, 16#b5#, 16#e8#, 16#ea#, 16#d0#, 16#44#, 16#0e#,
         16#20#, 16#b6#, 16#e8#, 16#db#, 16#09#, 16#d8#, 16#81#, 16#a7#,
         16#c6#, 16#13#, 16#2f#, 16#42#, 16#0e#, 16#52#, 16#79#, 16#50#,
         16#42#, 16#bd#, 16#fa#, 16#77#, 16#73#, 16#d8#, 16#a9#, 16#05#,
         16#14#, 16#47#, 16#b3#, 16#29#, 16#1c#, 16#e1#, 16#41#, 16#1c#,
         16#68#, 16#04#, 16#65#, 16#55#, 16#2a#, 16#a6#, 16#c4#, 16#05#,
         16#b7#, 16#76#, 16#4d#, 16#5e#, 16#87#, 16#be#, 16#a8#, 16#5a#,
         16#d0#, 16#0f#, 16#84#, 16#49#, 16#ed#, 16#8f#, 16#72#, 16#d0#,
         16#d6#, 16#62#, 16#ab#, 16#05#, 16#26#, 16#91#, 16#ca#, 16#66#,
         16#42#, 16#4b#, 16#c8#, 16#6d#, 16#2d#, 16#f8#, 16#0e#, 16#a4#,
         16#1f#, 16#43#, 16#ab#, 16#f9#, 16#37#, 16#d3#, 16#25#, 16#9d#,
         16#c4#, 16#b2#, 16#d0#, 16#df#, 16#b4#, 16#8a#, 16#6c#, 16#91#,
         16#39#, 16#dd#, 16#d7#, 16#f7#, 16#69#, 16#66#, 16#e9#, 16#28#,
         16#e6#, 16#35#, 16#55#, 16#3b#, 16#a7#, 16#6c#, 16#5c#, 16#87#,
         16#9d#, 16#7b#, 16#35#, 16#d4#, 16#9e#, 16#b2#, 16#e6#, 16#2b#,
         16#08#, 16#71#, 16#cd#, 16#ac#, 16#63#, 16#89#, 16#39#, 16#e2#,
         16#5e#, 16#8a#, 16#1e#, 16#0e#, 16#f9#, 16#d5#, 16#28#, 16#0f#,
         16#a8#, 16#ca#, 16#32#, 16#8b#, 16#35#, 16#1c#, 16#3c#, 16#76#,
         16#59#, 16#89#, 16#cb#, 16#cf#, 16#3d#, 16#aa#, 16#8b#, 16#6c#,
         16#cc#, 16#3a#, 16#af#, 16#9f#, 16#39#, 16#79#, 16#c9#, 16#2b#,
         16#37#, 16#20#, 16#fc#, 16#88#, 16#dc#, 16#95#, 16#ed#, 16#84#,
         16#a1#, 16#be#, 16#05#, 16#9c#, 16#64#, 16#99#, 16#b9#, 16#fd#,
         16#a2#, 16#36#, 16#e7#, 16#e8#, 16#18#, 16#b0#, 16#4b#, 16#0b#,
         16#c3#, 16#9c#, 16#1e#, 16#87#, 16#6b#, 16#19#, 16#3b#, 16#fe#,
         16#55#, 16#69#, 16#75#, 16#3f#, 16#88#, 16#12#, 16#8c#, 16#c0#,
         16#8a#, 16#aa#, 16#9b#, 16#63#, 16#d1#, 16#a1#, 16#6f#, 16#80#,
         16#ef#, 16#25#, 16#54#, 16#d7#, 16#18#, 16#9c#, 16#41#, 16#1f#,
         16#58#, 16#69#, 16#ca#, 16#52#, 16#c5#, 16#b8#, 16#3f#, 16#a3#,
         16#6f#, 16#f2#, 16#16#, 16#b9#, 16#c1#, 16#d3#, 16#00#, 16#62#,
         16#be#, 16#bc#, 16#fd#, 16#2d#, 16#c5#, 16#bc#, 16#e0#, 16#91#,
         16#19#, 16#34#, 16#fd#, 16#a7#, 16#9a#, 16#86#, 16#f6#, 16#e6#,
         16#98#, 16#ce#, 16#d7#, 16#59#, 16#c3#, 16#ff#, 16#9b#, 16#64#,
         16#77#, 16#33#, 16#8f#, 16#3d#, 16#a4#, 16#f9#, 16#cd#, 16#85#,
         16#14#, 16#ea#, 16#99#, 16#82#, 16#cc#, 16#af#, 16#b3#, 16#41#,
         16#b2#, 16#38#, 16#4d#, 16#d9#, 16#02#, 16#f3#, 16#d1#, 16#ab#,
         16#7a#, 16#c6#, 16#1d#, 16#d2#, 16#9c#, 16#6f#, 16#21#, 16#ba#,
         16#5b#, 16#86#, 16#2f#, 16#37#, 16#30#, 16#e3#, 16#7c#, 16#fd#,
         16#c4#, 16#fd#, 16#80#, 16#6c#, 16#22#, 16#f2#, 16#21#);
   begin
      Key_Setup (X, Key, 256, 0);
      IV_Setup (X, IV);
      Block_Counter_Setup (X, Block_Counter);
      Encrypt_Bytes (X, M, C, M'Length);
      if C /= Ciphertext then
         return False;
      end if;
      return True;
   end Test_2;

   function Test_3 return Boolean
   is
      X : ChaCha20 := ChaCha20'(Input => (others => 0));
      Key : constant Data_Type (0 .. 32 - 1) :=
        (16#1c#, 16#92#, 16#40#, 16#a5#, 16#eb#, 16#55#, 16#d3#, 16#8a#,
         16#f3#, 16#33#, 16#88#, 16#86#, 16#04#, 16#f6#, 16#b5#, 16#f0#,
         16#47#, 16#39#, 16#17#, 16#c1#, 16#40#, 16#2b#, 16#80#, 16#09#,
         16#9d#, 16#ca#, 16#5c#, 16#bc#, 16#20#, 16#70#, 16#75#, 16#c0#);
      IV : constant Data_Type (0 .. 12 - 1) :=
        (16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#02#);
      Block_Counter : constant Unsigned_32 := 42;
      M : constant Data_Type :=
        (16#27#, 16#54#, 16#77#, 16#61#, 16#73#, 16#20#, 16#62#, 16#72#,
         16#69#, 16#6c#, 16#6c#, 16#69#, 16#67#, 16#2c#, 16#20#, 16#61#,
         16#6e#, 16#64#, 16#20#, 16#74#, 16#68#, 16#65#, 16#20#, 16#73#,
         16#6c#, 16#69#, 16#74#, 16#68#, 16#79#, 16#20#, 16#74#, 16#6f#,
         16#76#, 16#65#, 16#73#, 16#0a#, 16#44#, 16#69#, 16#64#, 16#20#,
         16#67#, 16#79#, 16#72#, 16#65#, 16#20#, 16#61#, 16#6e#, 16#64#,
         16#20#, 16#67#, 16#69#, 16#6d#, 16#62#, 16#6c#, 16#65#, 16#20#,
         16#69#, 16#6e#, 16#20#, 16#74#, 16#68#, 16#65#, 16#20#, 16#77#,
         16#61#, 16#62#, 16#65#, 16#3a#, 16#0a#, 16#41#, 16#6c#, 16#6c#,
         16#20#, 16#6d#, 16#69#, 16#6d#, 16#73#, 16#79#, 16#20#, 16#77#,
         16#65#, 16#72#, 16#65#, 16#20#, 16#74#, 16#68#, 16#65#, 16#20#,
         16#62#, 16#6f#, 16#72#, 16#6f#, 16#67#, 16#6f#, 16#76#, 16#65#,
         16#73#, 16#2c#, 16#0a#, 16#41#, 16#6e#, 16#64#, 16#20#, 16#74#,
         16#68#, 16#65#, 16#20#, 16#6d#, 16#6f#, 16#6d#, 16#65#, 16#20#,
         16#72#, 16#61#, 16#74#, 16#68#, 16#73#, 16#20#, 16#6f#, 16#75#,
         16#74#, 16#67#, 16#72#, 16#61#, 16#62#, 16#65#, 16#2e#);
      C : Data_Type (0 .. M'Length - 1) := (others => 0);

      Ciphertext : constant Data_Type :=
        (16#62#, 16#e6#, 16#34#, 16#7f#, 16#95#, 16#ed#, 16#87#, 16#a4#,
         16#5f#, 16#fa#, 16#e7#, 16#42#, 16#6f#, 16#27#, 16#a1#, 16#df#,
         16#5f#, 16#b6#, 16#91#, 16#10#, 16#04#, 16#4c#, 16#0d#, 16#73#,
         16#11#, 16#8e#, 16#ff#, 16#a9#, 16#5b#, 16#01#, 16#e5#, 16#cf#,
         16#16#, 16#6d#, 16#3d#, 16#f2#, 16#d7#, 16#21#, 16#ca#, 16#f9#,
         16#b2#, 16#1e#, 16#5f#, 16#b1#, 16#4c#, 16#61#, 16#68#, 16#71#,
         16#fd#, 16#84#, 16#c5#, 16#4f#, 16#9d#, 16#65#, 16#b2#, 16#83#,
         16#19#, 16#6c#, 16#7f#, 16#e4#, 16#f6#, 16#05#, 16#53#, 16#eb#,
         16#f3#, 16#9c#, 16#64#, 16#02#, 16#c4#, 16#22#, 16#34#, 16#e3#,
         16#2a#, 16#35#, 16#6b#, 16#3e#, 16#76#, 16#43#, 16#12#, 16#a6#,
         16#1a#, 16#55#, 16#32#, 16#05#, 16#57#, 16#16#, 16#ea#, 16#d6#,
         16#96#, 16#25#, 16#68#, 16#f8#, 16#7d#, 16#3f#, 16#3f#, 16#77#,
         16#04#, 16#c6#, 16#a8#, 16#d1#, 16#bc#, 16#d1#, 16#bf#, 16#4d#,
         16#50#, 16#d6#, 16#15#, 16#4b#, 16#6d#, 16#a7#, 16#31#, 16#b1#,
         16#87#, 16#b5#, 16#8d#, 16#fd#, 16#72#, 16#8a#, 16#fa#, 16#36#,
         16#75#, 16#7a#, 16#79#, 16#7a#, 16#c1#, 16#88#, 16#d1#);
   begin
      Key_Setup (X, Key, 256, 0);
      IV_Setup (X, IV);
      Block_Counter_Setup (X, Block_Counter);
      Encrypt_Bytes (X, M, C, M'Length);
      if C /= Ciphertext then
         return False;
      end if;
      return True;
   end Test_3;

   function Run_Tests return Boolean
   is
   begin
      if Test_Quarter_Round
        and then Test_1 and then Test_2 and then Test_3
      then
         return True;
      end if;
      return False;
   end Run_Tests;

end ChaCha20;
