package client

import (
	"encoding/hex"
	"encoding/json"
	"strconv"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// For creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

/*
Secure File Storage and Access Control System
-------------------------------------------------
This project provides secure file storage, retrieval, sharing, and access revocation functionalities.
It ensures:
  - User authentication with encrypted credentials
  - Secure file storage using symmetric and asymmetric encryption
  - File integrity via digital signatures
  - Controlled file sharing with access revocation

Core Features:
  - InitUser: Create a new user account
  - GetUser: Retrieve an existing user
  - StoreFile: Securely store or overwrite a file
  - LoadFile: Retrieve a file’s content securely
  - AppendToFile: Append content securely to an existing file
  - CreateInvitation: Generate a secure file-sharing invitation
  - AcceptInvitation: Accept a shared file
  - RevokeAccess: Remove file access from another user
*/

// Entry stores encrypted data and its signature to ensure confidentiality and integrity.
type Entry struct {
	EncData   []byte
	Signature []byte
}

// User structure holds authentication details and cryptographic keys.
type User struct {
	Username string
	Password string
	DecKey   userlib.PKEDecKey
	SignKey  userlib.DSSignKey
}

// FileInfo stores metadata required for secure file handling and sharing.
//
// Head: contains the uuid of the file (hashed)
// SymKey: symmetric encryption key to encrypt and decrypt the file
// VerKey: verification key used to verify the integrity of the file
// SignKey: signature key used to sign the file
// AppendNumber: number of times the file has been appended
// Root: boolean that indicates if the FileInfo is the root of the tree
// OwnVerKey: verification key of the owner of the file
type FileInfo struct {
	Head         []byte
	SymKey       []byte
	VerKey       userlib.DSVerifyKey
	SignKey      userlib.DSSignKey
	AppendNumber int
	Root         bool
	OwnVerKey    []byte
}

// Invitation allows secure file-sharing by transmitting necessary cryptographic details.
// - Head: uuid of the file (hashed)
// - SymKey: symmetric encryption key to encrypt and decrypt the file
// - OwnersStorKey: verification key of the owner of the file
type Invitation struct {
	Head          []byte
	SymKey        []byte
	OwnersStorKey []byte
}

// InitUser registers a new user in the system.
//
// This function generates public-private key pairs for encryption
// and signing, securely stores the user data in the Datastore, and
// registers the public keys in the Keystore.
//
// Parameters:
// - username: Unique identifier for the user.
// - password: Used to derive an encryption key for secure storage.
//
// Returns:
// - userdataptr: Pointer to the newly created User struct.
// - err: Error if user registration fails (e.g., username already exists).
func InitUser(username string, password string) (userdataptr *User, err error) {
	// Validate username
	if len(username) < 1 {
		return nil, errors.New("Username must be at least a single character")
	}

	// Creating a uuid from username and checking if such usename already exist
	storageKeyHashed := HashedUuid(username)
	storageKey, err := uuid.FromBytes(storageKeyHashed)
	if err != nil {
		return nil, err
	}
	_, ok := userlib.DatastoreGet(storageKey)
	if ok {
		return nil, errors.New("Username already exist!")
	}

	// Generate public-private keys for encryption/decryption and sign/verify
	encKey, decKey, err := userlib.PKEKeyGen()
	if err != nil {
		return
	}
	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return
	}

	// Store public keys to Keystore
	err = userlib.KeystoreSet(username, encKey)
	if err != nil {
		return userdataptr, errors.New("Keystore error for Public Key.")
	}
	hashedVerKey := HashedUuid(username + "/mac")
	err = userlib.KeystoreSet(hex.EncodeToString(hashedVerKey), verifyKey)
	if err != nil {
		return userdataptr, errors.New("Keystore error for Verify Key.")
	}

	// Create UUID for user struct, marshal and encrypt before storing on Datastore
	new_pass := hex.EncodeToString(userlib.Hash([]byte(username + password + "This is how we do it"))[:16])
	userdata := User{username, new_pass, decKey, signKey}
	entryBytes, err := MarshEncSign(userdata, userlib.Hash([]byte(username + password + "This is how we do it"))[:16], signKey)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(storageKey, entryBytes)

	return &userdata, nil
}

// GetUser authenticates a user and retrieves their data from storage.
//
// The function decrypts the stored user data using the provided password,
// verifies its integrity, and reconstructs the User struct.
//
// Parameters:
// - username: The name of the user attempting to log in.
// - password: The password used for decryption.
//
// Returns:
// - userdataptr: Pointer to the authenticated User struct.
// - err: Error if authentication fails (e.g., incorrect password or data tampering).
func GetUser(username string, password string) (userdataptr *User, err error) {
	hashedKey := userlib.Hash([]byte(username + password + "This is how we do it"))[:16]
	hashedUuid := HashedUuid(username)
	userDecBytes, err := GetContent(hashedUuid, username, hashedKey)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(userDecBytes, &userdataptr)
	if err != nil {
		return nil, err
	}

	return
}

// StoreFile securely stores a file for a user.
//
// If the file already exists, its content is overwritten if the user is the owner.
// Otherwise, access validation is performed before modification. The file is
// symmetrically encrypted, signed, and saved.
//
// Parameters:
// - filename: The name of the file to store.
// - content: The byte content of the file.
//
// Returns:
// - err: Error if file storage fails.

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Check if file already exists in the Datastore. If so, overwrite its content if the user is the owner.
	// Otherwise, check if the user still has access to it (access could have been revoked).
	mainUuidHash := HashedUuid(userdata.Username + "/" + filename)
	mainUuidBytes, err := uuid.FromBytes(mainUuidHash)
	if err != nil {
		return
	}
	var fileVerKey userlib.DSVerifyKey
	var signKey, fileSignKey userlib.DSSignKey
	var fileUuidHashed, fileSymKey, accessUuidHashed, accessSymKey, symKey []byte
	var rootInfo FileInfo

	_, ok := userlib.DatastoreGet(mainUuidBytes)
	if ok {
		// Retrieve the existing file content.

		fileStuffBytes, err := GetContent(mainUuidHash, userdata.Username, userlib.Hash([]byte(userdata.Username + userdata.Password + filename))[:16])
		if err != nil {
			return errors.New("Error retrieving the original content in StoreFile")
		}
		var fileStuff FileInfo
		err = json.Unmarshal(fileStuffBytes, &fileStuff)
		if err != nil {
			return errors.New("Error unmarshalling original content in StoreFile")
		}
		// Traverse the tree to reach the accessFile. We are either the owner of the original file or not.
		// If we're the owners, then no problem should occur. If not, we might have our access revoked, so we will be alarmed.
		fileStuff, rootInfo, _, err = TraverseFiles(fileStuff)
		if err != nil {
			return err
		}
		// Collect info regarding the already previously saved file content (we will overwrite the content).
		fileUuidHashed = fileStuff.Head
		fileSymKey = fileStuff.SymKey
		fileSignKey = fileStuff.SignKey
		fileVerKey = fileStuff.VerKey

		// Collect info regarding rootFile (accessFile).
		accessSymKey = rootInfo.SymKey
		accessUuidHashed = rootInfo.Head
	} else {
		// Create randomly generated uuid for raw file and access pointers, along with randomly generated SymKey that would be used to encrypt access and raw file.
		fileUuidHashed = HashedUuid(string(userlib.RandomBytes(30)))
		fileSymKey = userlib.Hash(userlib.RandomBytes(20))[:16]
		accessUuidHashed = HashedUuid(string(userlib.RandomBytes(30)))
		accessSymKey = userlib.Hash(userlib.RandomBytes(20))[:16]

		// Create key pair to sign and verify the file each time we access/append it.
		fileSignKey, fileVerKey, err = userlib.DSKeyGen()
		if err != nil {
			return err
		}

		// Since we are not going to overwrite the mainFile in case we are not the owners,
		// we will do it here to create the initial fileInfo for owner.
		mainUuidHash = HashedUuid(userdata.Username + "/" + filename)
		symKey = userlib.Hash([]byte(userdata.Username + userdata.Password + filename))[:16]
		signKey = userdata.SignKey
		mainFile := FileInfo{accessUuidHashed, accessSymKey, fileVerKey, fileSignKey, 0, false, nil}
		err = SaveData(mainFile, symKey, signKey, mainUuidHash)
		if err != nil {
			return err
		}
	}

	// Upload the content onto the Datastore. If above ensured that the corresponding
	// uuid's, signatures and symkeys are good. We are putting content into Entry into Entry.EncContent (so, it would be marshalled and encrypted).
	err = SaveData(content, fileSymKey, fileSignKey, fileUuidHashed)
	if err != nil {
		return err
	}

	// Info of where to find raw file and how to decrypt it.
	accessData := FileInfo{fileUuidHashed, fileSymKey, fileVerKey, fileSignKey, 0, true, nil}
	err = SaveData(accessData, accessSymKey, fileSignKey, accessUuidHashed)
	if err != nil {
		return err
	}
	return
}

// SaveData encrypts, signs, and stores structured data.
//
// The input data is marshalled, symmetrically encrypted, and signed before
// being stored in the Datastore under the given UUID.
//
// Parameters:
// - data: The struct to be stored.
// - symKey: The symmetric key for encryption.
// - signKey: The private key for signing.
// - mainUuidHash: Hashed UUID determining the storage location.
//
// Returns:
// - err: Error if data storage fails.
func SaveData(data interface{}, symKey []byte, signKey userlib.DSSignKey, mainUuidHash []byte) error {
	mainFileBytes, err := MarshEncSign(data, symKey, signKey)
	if err != nil {
		return err
	}
	mainUuid, err := uuid.FromBytes(mainUuidHash)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(mainUuid, mainFileBytes)
	return nil
}

// AppendToFile securely appends data to an existing file.
//
// If the user is not the owner, access validation is performed.
// The appended content is symmetrically encrypted and stored separately,
// with references updated to maintain the correct order.
//
// Parameters:
// - filename: The name of the file to append to.
// - content: The byte content to append.
//
// Returns:
// - err: Error if the operation fails.
func (userdata *User) AppendToFile(filename string, content []byte) error {
	// Get the main file content out from username + filenmae uuid

	mainUuidHashed := HashedUuid(userdata.Username + "/" + filename)
	hashedKey := userlib.Hash([]byte(userdata.Username + userdata.Password + filename))[:16]
	fileStuffBytes, err := GetContent(mainUuidHashed, userdata.Username, hashedKey)
	if err != nil {
		return err
	}

	// Unmarshal the bytes into FileInfo struct
	var rootFile, prevFile FileInfo
	err = json.Unmarshal(fileStuffBytes, &rootFile)
	if err != nil {
		return err
	}

	// Traverse the tree to get to Root file. If user is not the owner, this would also check if user has access to it
	// RootStuff contains info about access point.
	rootFile, prevFile, _, err = TraverseFiles(rootFile)
	if err != nil {
		return err
	}

	// Save the appended content onto mainFile Uuid + append + cuurent number of appends
	appendUuidHashed := HashedUuid(string(rootFile.Head) + "append" + strconv.Itoa(rootFile.AppendNumber))
	err = SaveData(content, rootFile.SymKey, rootFile.SignKey, appendUuidHashed)
	if err != nil {
		return err
	}

	// Update the number of appends in rootFile. Will need to save it back at the end.
	rootFile.AppendNumber += 1
	err = SaveData(rootFile, prevFile.SymKey, prevFile.SignKey, prevFile.Head)
	return nil
}

// LoadFile retrieves and decrypts a stored file.
//
// Parameters:
// - filename: The name of the file to retrieve.
//
// Returns:
// - content: The decrypted file content.
// - err: Error if retrieval fails (e.g., file not found or access revoked).
func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Construct the UUID for the main file using the username and filename
	mainUuidHashed := HashedUuid(userdata.Username + "/" + filename)
	hashedKey := userlib.Hash([]byte(userdata.Username + userdata.Password + filename))[:16]

	// Retrieve the encrypted file metadata from the Datastore
	fileStuffBytes, err := GetContent(mainUuidHashed, userdata.Username, hashedKey)
	if err != nil {
		return
	}

	// Unmarshal the metadata into a FileInfo struct
	var rootFile FileInfo
	err = json.Unmarshal(fileStuffBytes, &rootFile)
	if err != nil {
		return
	}

	// Traverse the access control tree to find the root file
	rootFile, _, _, err = TraverseFiles(rootFile)
	if err != nil {
		return content, err
	}

	// Retrieve and decrypt the main file content
	contentBytes, err := RetrieveCont(rootFile.Head, rootFile.SymKey, rootFile.VerKey)
	if err != nil {
		return
	}

	// Unmarshal the main content into the content variable
	err = json.Unmarshal(contentBytes, &content)
	if err != nil {
		return content, err
	}

	// Append any additional content from appended files
	var totalAppends, currAppend int = rootFile.AppendNumber, 0
	var appends []byte
	for currAppend < totalAppends {
		// Construct the UUID for each appended file
		appendUuidHashed := HashedUuid(string(rootFile.Head) + "append" + strconv.Itoa(currAppend))

		// Retrieve and decrypt each appended content
		appendsBytes, err := RetrieveCont(appendUuidHashed, rootFile.SymKey, rootFile.VerKey)
		if err != nil {
			return content, err
		}

		// Unmarshal the appended content and append it to the main content
		err = json.Unmarshal(appendsBytes, &appends)
		if err != nil {
			return content, err
		}
		content = append(content, appends...)
		currAppend += 1
	}
	return
}

// CreateInvitation generates a secure invitation for a file.
//
// This function creates an encrypted and signed invitation that allows
// another user to access a shared file. It ensures the recipient has a valid
// Keystore entry before proceeding.
//
// Parameters:
// - filename: The name of the file being shared.
// - recipientUsername: The username of the recipient.
//
// Returns:
// - invitationPtr: A UUID pointing to the created invitation.
// - err: Error if the invitation cannot be created.
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// Checking if the recipient user exists in the Keystore
	_, ok := userlib.KeystoreGet(recipientUsername)
	if !ok {
		return invitationPtr, errors.New("No such recipient exists!")
	}

	// Retrieving the file content
	mainUuidHash := HashedUuid(userdata.Username + "/" + filename)
	hashedMainKey := userlib.Hash([]byte(userdata.Username + userdata.Password + filename))[:16]
	fileStuffBytes, err := GetContent(mainUuidHash, userdata.Username, hashedMainKey)
	if err != nil {
		return
	}

	var originalFile FileInfo
	err = json.Unmarshal(fileStuffBytes, &originalFile)
	if err != nil {
		return
	}

	// Traversing the access control tree to check if the user is the owner or not
	// If level == 1, then the user is the owner
	_, prevFile, level, err := TraverseFiles(originalFile)
	if err != nil {
		return
	}

	invitationPtr = uuid.New()

	var inviteBytes []byte
	var inviteFile Invitation
	if level == 1 {
		// If the user is the owner, then create an access file
		// The access file is encrypted with a random SymKey and contains the
		// necessary information for the recipient to access the file
		accessUuidHash := HashedUuid(userdata.Username + "/" + recipientUsername + "/" + filename)
		accessSymKey := userlib.RandomBytes(16)

		err = SaveData(prevFile, accessSymKey, userdata.SignKey, accessUuidHash)
		if err != nil {
			return invitationPtr, errors.New("Could not save the access file!")
		}

		// Create the invitation which contains the UUID of the access file,
		// the SymKey to encrypt the file, and the hashed username of the owner
		// to retrieve the owner's verification key when the recipient accepts the invitation
		inviteFile = Invitation{accessUuidHash, accessSymKey, HashedUuid(userdata.Username + "/mac")}

	} else {
		// If the user is not the owner, then the invitation is a copy of the originalFile
		// this is an option where the sharer is not the owner. In this case, origianlFile already contains all necessary information (current sharer and new sharer are
		// pointing to the same file since we do not care what happens when non-owners revoke access)
		// so we would simply give the copy of it as an invitation.
		inviteFile = Invitation{originalFile.Head, originalFile.SymKey, originalFile.OwnVerKey}
	}

	inviteBytes, err = MarshPEncSign(inviteFile, recipientUsername, userdata.SignKey)
	if err != nil {
		return invitationPtr, err
	}

	userlib.DatastoreSet(invitationPtr, inviteBytes)

	return
}

// AcceptInvitation processes and validates a received invitation.
//
// This function decrypts the invitation, verifies its validity, and registers
// access to the shared file under their own namespace.
//
// Parameters:
// - senderUsername: The user who sent the invitation.
// - invitationPtr: UUID pointing to the invitation entry.
// - filename: The filename under which the recipient will store the access information.
//
// Returns:
// - err: Error if the invitation is invalid or cannot be processed.
func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// Checking if user already has a file with the same name
	mainUuidHash := HashedUuid(userdata.Username + "/" + filename)
	mainUuid, err := uuid.FromBytes(mainUuidHash)
	if err != nil {
		return errors.New("Could not create Uuid in accept invitation")
	}
	_, ok := userlib.DatastoreGet(mainUuid)
	if ok {
		return errors.New("You already have a file with the same username!")
	}

	// Retrieving the content out of Invitation (where uuid points to)
	invite, err := GetPEncContent(invitationPtr, senderUsername, userdata.DecKey)
	if err != nil {
		return errors.New("Could not decrypt the invitation")
	}

	// Constructing the fileInfo type for the recipient user. It would point to the file where the invitation.Uuid points to (accessPoint)
	verKey, ok := userlib.KeystoreGet(hex.EncodeToString(invite.OwnersStorKey))
	if !ok {
		return errors.New("Could not get verification key!")
	}
	var dummySign userlib.DSSignKey
	dummyAppends := 0
	root := false

	recipientFileStuff := FileInfo{invite.Head, invite.SymKey, verKey, dummySign, dummyAppends, root, invite.OwnersStorKey}

	// Checking if after tree traversal no error occured, then invitation is and access file is still valid
	_, _, _, err = TraverseFiles(recipientFileStuff)
	if err != nil {
		return errors.New("Invitation no longer valid!")
	}

	// Encrypting the recipientFileStuff and signing it with the recipient's private key
	symKey := userlib.Hash([]byte(userdata.Username + userdata.Password + filename))[:16]
	recipientFileBytes, err := MarshEncSign(recipientFileStuff, symKey, userdata.SignKey)
	if err != nil {
		return err
	}

	// Storing the recipientFileBytes in the Datastore under the recipient's namespace
	userlib.DatastoreSet(mainUuid, recipientFileBytes)
	return nil
}

// RevokeAccess removes access to a previously shared file.
//
// The function invalidates the recipient’s access by re-encrypting
// the access file with random data, effectively making it unreadable.
//
// Parameters:
// - filename: The name of the file being revoked.
// - recipientUsername: The user whose access is being revoked.
//
// Returns:
// - err: Error if access revocation fails.
func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {

	// Check if we have file in our filespace
	mainUuidHash := HashedUuid(userdata.Username + "/" + filename)
	mainUuid, err := uuid.FromBytes(mainUuidHash)
	if err != nil {
		return errors.New("Could not create Uuid in accept invitation")
	}
	_, ok := userlib.DatastoreGet(mainUuid)
	if !ok {
		return errors.New("You don't have such filename!")
	}

	accessUuidHash := HashedUuid(userdata.Username + "/" + recipientUsername + "/" + filename)
	accessUuid, err := uuid.FromBytes(accessUuidHash)
	accessFile, ok := userlib.DatastoreGet(accessUuid)
	if !ok {
		return errors.New("The file is not being shared with the user!")
	}

	var accessEntry Entry
	err = json.Unmarshal(accessFile, &accessEntry)
	if err != nil {
		return err
	}
	reEncCont := SymEncrypt(userlib.RandomBytes(16), accessEntry.EncData)

	newEntry := Entry{reEncCont, accessEntry.Signature}
	newEntryBytes, err := json.Marshal(newEntry)
	if err != nil {
		return errors.New("Could not marshal the entry!")
	}

	userlib.DatastoreSet(accessUuid, newEntryBytes)

	userlib.DatastoreDelete(accessUuid)
	return nil
}

// SymEncrypt encrypts the provided data using AES symmetric encryption.
//
// A new random IV (Initialization Vector) is generated for each encryption
// operation to ensure security. The data is encrypted using the provided
// symmetric key.
//
// Parameters:
// - symKey: The symmetric encryption key (16-byte AES key).
// - data: The plaintext data to be encrypted.
//
// Returns:
// - The encrypted byte array.
func SymEncrypt(symKey []byte, data []byte) []byte {
	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	return userlib.SymEnc(symKey, iv, data)
}

// GetUnmarshal retrieves and unmarshals stored data from the Datastore.
//
// The function fetches an `Entry` struct from the Datastore using a hashed UUID,
// then unmarshals it into an `Entry` type.
//
// Parameters:
// - key: A hashed key (UUID) representing the data location.
//
// Returns:
// - data: The unmarshalled `Entry` struct.
// - err: Error if the data cannot be retrieved or unmarshalled.
func GetUnmarshal(key []byte) (data Entry, err error) {
	// Create a uuid of where to find an info of file
	storageKey, err := uuid.FromBytes(key)

	if err != nil {
		return data, err
	}

	// Check if such file exist
	initialFileBytes, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return data, errors.New("No such file exist!")
	}

	// Unpack the file
	err = json.Unmarshal(initialFileBytes, &data)
	if err != nil {
		return data, err
	}
	return
}

// VerifyContent checks the integrity of encrypted data using digital signatures.
//
// The function retrieves the verification key associated with the provided
// username, then verifies that the given data has not been tampered with.
//
// Parameters:
// - username: The username whose verification key is used.
// - data: The encrypted data to be verified.
// - sig: The digital signature to check.
//
// Returns:
// - err: Error if the signature does not match or if the key is missing.
func VerifyContent(username string, data []byte, sig []byte) error {
	hashedVerKey := HashedUuid(username + "/mac")
	verKey, ok := userlib.KeystoreGet(hex.EncodeToString(hashedVerKey))
	if !ok {
		return errors.New("Could not find the verification key in KeyStore!")
	}
	err := userlib.DSVerify(verKey, data, sig)
	if err != nil {
		return errors.New("Could not verify the content!")
	}
	return nil
}

// MarshEncSign marshals, encrypts, and signs the provided content.
//
// The function serializes the input, encrypts it with a symmetric key, then signs
// the encrypted data with a digital signature.
//
// Parameters:
// - content: The data to be stored (typically a struct).
// - symKey: The symmetric encryption key.
// - signKey: The signing key used to generate a digital signature.
//
// Returns:
// - marshCont: The marshalled, encrypted, and signed byte array.
// - err: Error if any operation fails.
func MarshEncSign(content interface{}, symKey []byte, signKey userlib.DSSignKey) (marshCont []byte, err error) {

	contentBytes, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}
	encContent := SymEncrypt(symKey, contentBytes)

	signedContent, err := userlib.DSSign(signKey, encContent)
	if err != nil {
		return nil, err
	}

	contentEntry := Entry{encContent, signedContent}

	marshCont, err = json.Marshal(contentEntry)
	if err != nil {
		return nil, err
	}
	return
}

// MarshPEncSign marshals, encrypts (using public-key encryption), and signs content.
//
// This function is used to securely share data between users. The content is
// encrypted with the recipient's public key and signed with the sender’s signing key.
//
// Parameters:
// - content: The `Invitation` struct containing sharing details.
// - username: The recipient's username (used to retrieve their public key).
// - signKey: The sender's signing key.
//
// Returns:
// - marshCont: The marshalled, encrypted, and signed byte array.
// - err: Error if encryption or signing fails.
func MarshPEncSign(content Invitation, username string, signKey userlib.DSSignKey) (marshCont []byte, err error) {
	// Marshall content
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}

	// Retrieve publiv key
	pubKey, ok := userlib.KeystoreGet(username)
	if !ok {
		return marshCont, errors.New("Could not get Public Key!")
	}

	// Encrypt using public encryption key
	encContent, err := userlib.PKEEnc(pubKey, contentBytes)
	if err != nil {
		return
	}

	// Sign the content
	signedContent, err := userlib.DSSign(signKey, encContent)
	if err != nil {
		return
	}

	contentEntry := Entry{encContent, signedContent}

	// Marshall the Entry type
	marshCont, err = json.Marshal(contentEntry)
	if err != nil {
		return nil, err
	}
	return
}

// GetContent retrieves, verifies, and decrypts stored data.
//
// The function retrieves an `Entry` struct from the Datastore, verifies its
// signature, and decrypts the content using a symmetric key.
//
// Parameters:
// - key: Hashed UUID used to locate the data.
// - username: The username used to retrieve the verification key.
// - symKey: The symmetric key for decryption.
//
// Returns:
// - data: The decrypted byte array.
// - err: Error if retrieval, verification, or decryption fails.
func GetContent(key []byte, username string, symKey []byte) (data []byte, err error) {
	// Retrieve the encrypted data from the Datastore
	encryptedData, err := GetUnmarshal(key)
	if err != nil {
		return nil, err
	}

	// Verify the integrity of the data
	if err = VerifyContent(username, encryptedData.EncData, encryptedData.Signature); err != nil {
		return nil, err
	}

	// Decrypt the data using the symmetric key
	data = userlib.SymDec(symKey, encryptedData.EncData)

	return
}

// GetPEncContent retrieves, verifies, and decrypts publicly encrypted content.
//
// The function retrieves an encrypted `Entry` from the Datastore, verifies its
// integrity, then decrypts it using the recipient's private key.
//
// Parameters:
// - storageKey: UUID identifying the stored invitation data.
// - verificationUser: The sender's username (used for signature verification).
// - pDecKey: The recipient's private decryption key.
//
// Returns:
// - invite: The decrypted `Invitation` struct.
// - err: Error if retrieval, verification, or decryption fails.
func GetPEncContent(storageKey uuid.UUID, verificationUser string, pDecKey userlib.PKEDecKey) (invite Invitation, err error) {

	// Check if such file exist
	initialFileBytes, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return invite, errors.New("No such file exist!")
	}

	// Unmarshall the file
	var fileStuff Entry
	err = json.Unmarshal(initialFileBytes, &fileStuff)
	if err != nil {
		return
	}

	// Verify the content
	err = VerifyContent(verificationUser, fileStuff.EncData, fileStuff.Signature)
	if err != nil {
		return
	}

	// Decrypt the content. Decrypted content is a byte stream of FileInfo type.
	plaintext, err := userlib.PKEDec(pDecKey, fileStuff.EncData)
	if err != nil {
		return
	}

	err = json.Unmarshal(plaintext, &invite)
	if err != nil {
		return invite, err
	}
	return
}

// HashedUuid generates a fixed-length hash for a given key.
//
// This function hashes the input string and returns the first 16 bytes,
// ensuring UUID compatibility for secure storage lookup.
//
// Parameters:
// - storageKey: The string input to be hashed.
//
// Returns:
// - hashedKey: A 16-byte hashed key.
func HashedUuid(storageKey string) (hashedKey []byte) {
	hashedKey = userlib.Hash([]byte(storageKey))[:16]
	return
}

// TraverseFiles navigates the access control tree to find the root file.
//
// This function recursively follows file access pointers to determine
// the root access file and the immediate preceding file (if applicable).
//
// Parameters:
// - fileStuff: The `FileInfo` struct representing the current file.
//
// Returns:
// - rootFile: The `FileInfo` struct of the root file (original owner’s access).
// - accessFile: The `FileInfo` struct of the direct access point for the user.
// - iterations: The number of steps taken to reach the root.
// - err: Error if traversal fails.
func TraverseFiles(fileStuff FileInfo) (rootFile FileInfo, accessFile FileInfo, iterations int, err error) {
	root := fileStuff.Root
	iterations = 0
	for root != true {
		tempFileStuffBytes, err := RetrieveCont(fileStuff.Head, fileStuff.SymKey, fileStuff.VerKey)
		if err != nil {
			return rootFile, accessFile, iterations, err
		}
		err = json.Unmarshal(tempFileStuffBytes, &rootFile)
		if err != nil {
			return rootFile, accessFile, iterations, err
		}
		root = rootFile.Root
		accessFile = fileStuff
		fileStuff = rootFile
		iterations += 1
	}
	return
}

// RetrieveCont fetches and verifies encrypted file content.
//
// The function retrieves an `Entry` struct from storage, verifies its integrity
// using a digital signature, and decrypts the content using a symmetric key.
//
// Parameters:
// - uuid: The hashed UUID representing the file location.
// - symKey: The symmetric encryption key for decryption.
// - verKey: The verification key used to check the integrity.
//
// Returns:
// - contentBytes: The decrypted content as bytes.
// - err: Error if retrieval, verification, or decryption fails.
func RetrieveCont(uuid []byte, symKey []byte, verKey userlib.DSVerifyKey) (contentBytes []byte, err error) {

	fileEntry, err := GetUnmarshal(uuid)
	if err != nil {
		return
	}

	err = userlib.DSVerify(verKey, fileEntry.EncData, fileEntry.Signature)
	if err != nil {
		return nil, errors.New("Could not verify")
	}

	contentBytes = userlib.SymDec(symKey, fileEntry.EncData)
	return

}
