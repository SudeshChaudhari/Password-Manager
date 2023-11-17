// Built a C++ password manager app with user auth, hashing, and storage using Sodium for secure password management.

// g++ -c Password_Manager.cpp
// g++ -o Password_Manager Password_Manager.o -lsodium


// User1:123321
// User2:123
// User3:user3
// User4:user4



#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <cstdlib>
#include <limits>
#include <ctime>
#include <sstream>
#include <sodium.h>

using namespace std;

// Define a User structure
struct User
{
    string username;
    string hashedPassword;

    User(const string &name, const string &hashedPwd) : username(name), hashedPassword(hashedPwd) {}
};

// Define a UserManager class
class UserManager
{
private:
    vector<User> users;
    string userFile;

public:
    UserManager(const string &file) : userFile(file)
    {
        loadUserData();
    }

    // Function to create a new user (sign-up)
    bool createUser(const string &newUsername, const string &plainPassword)
    {
        string username = newUsername;

        // Generate a salt for password hashing
        unsigned char salt[crypto_pwhash_SALTBYTES];
        randombytes_buf(salt, sizeof salt);

        // Hash the user's password using libsodium
        unsigned char hashedPassword[crypto_pwhash_STRBYTES];
        if (crypto_pwhash_str(reinterpret_cast<char *>(hashedPassword), plainPassword.c_str(), plainPassword.size(),
                              crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
        {
            cerr << "Password hashing failed." << endl;
            return false;
        }

        while (true)
        {
            // Check if the username already exists
            auto it = find_if(users.begin(), users.end(),
                              [username](const User &user)
                              { return user.username == username; });

            if (it != users.end())
            {
                cout << "Username already exists. Please choose a different one or enter 'q' to quit: ";
                cin >> username;

                if (username == "q")
                {
                    return false;
                }
            }
            else
            {
                break;
            }
        }
        users.push_back(User(username, string(reinterpret_cast<char *>(hashedPassword))));
        saveUserData();
        cout << "User account created successfully!" << endl;
        return true;
    }

    // Function to authenticate a user (sign-in)
    bool authenticateUser(const string &username, const string &plainPassword)
    {
        auto it = find_if(users.begin(), users.end(),
                          [username](const User &user)
                          {
                            return user.username == username;
                          });
        if (it != users.end())
        {
            // Convert the plain password to a null-terminated string
            const char *plainPwd = plainPassword.c_str();

            // Verify the hashed password using libsodium
            return crypto_pwhash_str_verify(it->hashedPassword.c_str(), plainPwd, plainPassword.size()) == 0;
        }
        return false;
    }

    // Function to save user data to a file
    void saveUserData()
    {
        ofstream file(userFile);
        if (file.is_open())
        {
            for (const User &user : users)
            {
                file << user.username << ":" << user.hashedPassword << endl;
            }
            file.close();
        }
        else
        {
            cerr << "Unable to open user data file for saving." << endl;
        }
    }

    // Function to load user data from a file
    void loadUserData()
    {
        ifstream file(userFile);
        if (file.is_open())
        {
            users.clear();
            string line;
            while (getline(file, line))
            {
                size_t pos = line.find(':');
                if (pos != string::npos)
                {
                    string username = line.substr(0, pos);
                    string hashedPassword = line.substr(pos + 1);
                    users.push_back(User(username, hashedPassword));
                }
            }
            file.close();
        }
    }
};

// Define a Password structure
struct Password
{
    string username;
    string account;
    string password;

    Password(const string &user, const string &acc, const string &pwd)
        : username(user), account(acc), password(pwd) {}
};

// Define a PasswordManager class
class PasswordManager
{
private:
    vector<Password> passwords;

public:
    // Function to add a new password
    void addPassword(const string &username, const string &account, const string &password)
    {
        // Check if the account already exists for this user
        auto it = find_if(passwords.begin(), passwords.end(),
                          [username, account](const Password &pwd)
                          { return pwd.username == username && pwd.account == account; });

        if (it != passwords.end())
        {
            // Account exists, update the password
            it->password = password;
            cout << "Password updated for account: " << account << endl;
        }
        else
        {
            // Account does not exist, add a new password
            passwords.push_back(Password(username, account, password));
            cout << "Password added for account: " << account << endl;
        }
    }

    // Function to Get a password
    void getPassword(const string &username, const string &account)
    {
        auto it = find_if(passwords.begin(), passwords.end(),
                          [username, account](const Password &pwd)
                          { return pwd.username == username && pwd.account == account; });

        if (it != passwords.end())
        {
            cout << "Password for account " << account << ": " << it->password << endl;
        }
        else
        {
            cout << "Account not found." << endl;
        }
    }

    // Function to delete a password
    void deletePassword(const string &username, const string &account)
    {
        auto it = find_if(passwords.begin(), passwords.end(),
                          [username, account](const Password &pwd)
                          { return pwd.username == username && pwd.account == account; });

        if (it != passwords.end())
        {
            passwords.erase(it);
            cout << "Password for account " << account << " deleted." << endl;
        }
        else
        {
            cout << "Account not found." << endl;
        }
    }

    // Function to save passwords to a file
    void savePasswordsToFile(const string &filename)
    {
        ofstream file(filename);
        if (file.is_open())
        {
            for (const Password &pwd : passwords)
            {
                file << pwd.username << ":" << pwd.account << ":" << pwd.password << endl;
            }
            cout << "Changes updated to " << filename << " File." << endl;
            file.close();
        }
        else
        {
            cout << "Unable to open file for saving." << endl;
        }
    }

    // Function to load passwords from a file
    void loadPasswordsFromFile(const string &filename)
    {
        ifstream file(filename);
        if (file.is_open())
        {
            passwords.clear();
            string line;
            while (getline(file, line))
            {
                size_t pos1 = line.find(':');
                size_t pos2 = line.find(':', pos1 + 1);
                if (pos1 != string::npos && pos2 != string::npos)
                {
                    string username = line.substr(0, pos1);
                    string account = line.substr(pos1 + 1, pos2 - pos1 - 1);
                    string password = line.substr(pos2 + 1);
                    passwords.push_back(Password(username, account, password));
                }
            }
            file.close();
            cout << "Passwords loaded from " << filename << endl;
        }
        else
        {
            cout << "Unable to open file for loading." << endl;
            exit(EXIT_FAILURE); // Exit the program with an error code
        }
    }
};

// To create a strong Password
class StrongPasswordGenerator
{
private:
    int passwordLength;

    char getRandomCharacter(char lowerLimit, char upperLimit)
    {
        return lowerLimit + (rand() % (upperLimit - lowerLimit + 1));
    }

public:
    StrongPasswordGenerator(int length) : passwordLength(length)
    {
        srand(time(0));
    }

    string generateStrongPassword()
    {
        string password = "";

        for (int i = 0; i < passwordLength; i++)
        {
            char randomCharacter;
            int randomCharacterType = rand() % 4;

            switch (randomCharacterType)
            {
            case 0:
                randomCharacter = getRandomCharacter(33, 47);
                break;
            case 1:
                randomCharacter = getRandomCharacter(58, 64);
                break;
            case 2:
                randomCharacter = getRandomCharacter(97, 122);
                break;
            case 3:
                randomCharacter = getRandomCharacter(65, 90);
                break;
            }
            password += randomCharacter;
        }
        return password;
    }
};

int getInput(const string &prompt)
{
    int value;
    while (true)
    {
        cout << prompt;
        if (cin >> value)
        {
            break;
        }
        else
        {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input. ";
        }
    }
    return value;
}

int main()
{
    PasswordManager passwordManager;
    StrongPasswordGenerator passwordGenerator(12);
    string generatedPassword = passwordGenerator.generateStrongPassword();
    string userFile = "users.txt";
    UserManager userManager(userFile);

    int choice, Dec, ch;
    string account, password, filename, currentUsername;

    if (sodium_init() < 0)
    {
        cerr << "libsodium initialization failed, cannot proceed." << endl;
        return 1;
    }
    
    bool signedIn = false;

    do
    {
        cout << "1. Sign In\n2. Create Account\n3. Exit" << endl;
        ch = getInput("Enter your choice: ");

        switch (ch)
        {
        case 1: // Sign In
        {
            string enteredUsername, enteredPassword;
            bool signInSuccessful = false;
            int attempts = 3;
            while (attempts > 0)
            {
                cout << "Enter username: ";
                cin >> enteredUsername;
                cout << "Enter password: ";
                cin >> enteredPassword;

                if (userManager.authenticateUser(enteredUsername, enteredPassword))
                {
                    signedIn = true;
                    currentUsername = enteredUsername;
                    cout << "Sign-in successful. Welcome, " << enteredUsername << "!" << endl;
                    signInSuccessful = true;
                    break;
                }
                else
                {
                    cout << "Invalid username or password. Sign-in failed. " << attempts - 1 << " attempts remaining." << endl;
                    attempts--;
                }
            }
            if (!signInSuccessful)
            {
                cout << "Too many failed sign-in attempts. Exiting." << endl;
                return false;
            }
            break;
        }
        case 2: // Create Account
        {
            string newUsername, newPassword;
            cout << "Enter a new username: ";
            cin >> newUsername;
            cout << "Enter a password: ";
            cin >> newPassword;

            if (!userManager.createUser(newUsername, newPassword))
            {
                cout << "Exiting." << endl;
                return 0;
            }

            // Set the currentUsername to the newly created username
            currentUsername = newUsername;
            signedIn = true;
            break;
        }
        case 3: // Exit
            cout << "Exiting." << endl;
            return 0;
        default:
            cout << "Invalid choice." << endl;
            break;
        }

        if (signedIn)
        {
            cout << "Enter File name to save Passwords: " << endl;
            cin >> filename;
            passwordManager.loadPasswordsFromFile(filename);
        }

        do
        {
            cout << "Password Manager Menu:" << endl;
            cout << "1. Add/Update Password" << endl;
            cout << "2. Get Password" << endl;
            cout << "3. Delete Password" << endl;
            cout << "4. Sign Out" << endl;
            choice = getInput("Enter your choice: ");

            switch (choice)
            {
            case 1:
                cout << "Enter account name: ";
                cin >> account;
                cout << "Generated strong password: " << generatedPassword << endl;
                cout << "Do you want to add this password to the account? (1. Yes / 2. No): ";
                Dec = getInput("Enter your choice: ");
                switch (Dec)
                {
                case 1:
                    passwordManager.addPassword(currentUsername, account, generatedPassword);
                    passwordManager.savePasswordsToFile(filename);
                    break;
                case 2:
                    cout << "Enter password: ";
                    cin >> password;
                    passwordManager.addPassword(currentUsername, account, password);
                    passwordManager.savePasswordsToFile(filename);
                    break;
                default:
                    cout << "Invalid choice for password generation. Try again." << endl;
                    break;
                }
                break;
            case 2:
                cout << "Enter account name: ";
                cin >> account;
                passwordManager.getPassword(currentUsername, account);
                break;
            case 3:
                cout << "Enter account name: ";
                cin >> account;
                passwordManager.deletePassword(currentUsername, account);
                passwordManager.savePasswordsToFile(filename);
                break;
            case 4:
                cout << "Signing out." << endl;
                currentUsername = "";
                signedIn = false;
                break;
            default:
                cout << "Invalid choice. Try again." << endl;
                break;
            }
        } while (!currentUsername.empty());
    } while (ch != 3);
    return 0;
}