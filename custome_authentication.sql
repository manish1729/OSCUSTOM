http://www.poweroforacleapex.com/using-custom-authentication/

update user_repository
set account_status='UNLOCKED',
num_invalid_logins=0

commit

--Script for setting up custom authentication

--Step 1 - create user_repository table
CREATE TABLE user_repository(USER_ID NUMBER NOT NULL,
                             USERNAME VARCHAR2(8) NOT NULL,
                             USER_PASSWORD VARCHAR2 (20) NOT NULL,
                             FIRST_NAME VARCHAR2 (30) NOT NULL,
                             LAST_NAME VARCHAR2 (30) NOT NULL,
                             EMAIL VARCHAR2 (50) NOT NULL,
                             ACCOUNT_STATUS VARCHAR2(10) NOT NULL,
                             NUM_INVALID_LOGINS NUMBER NOT NULL, 
                             PRIMARY KEY(USER_ID)
                            );

--Step 2 - Insert a few sample users in above created table
INSERT INTO user_repository
VALUES(1, 'USER_01', 'user01_pass', 'Lewis', 'Hamilton', 'lewis.hamilton@gmail.com', 'UNLOCKED', 0);

INSERT INTO user_repository
VALUES(2, 'USER_02', 'user02_pass', 'Fernando', 'Alonso', 'fernando.alonso@gmail.com', 'UNLOCKED', 0);

COMMIT;

--Step 3 - Create our authentication package specification
CREATE OR REPLACE PACKAGE AUTHENTICATION_PKG
AS

  --Our custom authentication function
  FUNCTION authenticate_user(p_user_name_in IN OSCUSTOM_USERS.username%TYPE, p_password_in IN OSCUSTOM_USERS.user_password%TYPE)
      RETURN BOOLEAN;
   
   ---- Admin authentication
   FUNCTION authenticate_admin(p_user_name_in IN OSCUSTOM_USERS.username%TYPE, p_password_in IN OSCUSTOM_USERS.user_password%TYPE)
      RETURN BOOLEAN;
      
  --To retrieve the count of invalid logins for a user
  FUNCTION get_num_invalid_logins(p_username_in IN OSCUSTOM_USERS.username%TYPE)
      RETURN NUMBER;
      
  --To update the count of invalid logins when an unsuccessful authentication occurs
  PROCEDURE update_invalid_login_count(p_username_in IN OSCUSTOM_USERS.username%TYPE);

  --To lock a user account once a certain number of invalid login attempts have occurred
  PROCEDURE lock_user_account(p_username_in IN OSCUSTOM_USERS.username%TYPE);
          
END AUTHENTICATION_PKG;
/

--Step 4 - Create the authentication package body
CREATE OR REPLACE PACKAGE BODY AUTHENTICATION_PKG
AS

  
  FUNCTION authenticate_user(p_user_name_in IN OSCUSTOM_USERS.username%TYPE, p_password_in IN OSCUSTOM_USERS.user_password%TYPE)

      RETURN BOOLEAN
  
  AS
      
      l_username OSCUSTOM_USERS.USERNAME%TYPE := p_user_name_in;
      l_password OSCUSTOM_USERS.USER_PASSWORD%TYPE := p_password_in;
      l_count NUMBER := 0;
      l_failed_logins_count OSCUSTOM_USERS.NUM_INVALID_LOGINS%TYPE := 0;
      l_max_failed_logins CONSTANT NUMBER := 30;
      
  BEGIN
  
      --Verify if the user exists and has fewer than 3 invalid logins
      --If a record is found, access is granted
      SELECT COUNT(*)
      INTO l_count
      FROM OSCUSTOM_USERS A
      WHERE UPPER(A.USERNAME) = UPPER(l_username)
      AND A.USER_PASSWORD = l_password
      --AND NVL(A.ACCESS_CODE,'V') <>'A' --- not admin
      AND NVL(A.NUM_INVALID_LOGINS, 0) < l_max_failed_logins;
      
      IF l_count = 1
      THEN 
         --login credentials have been verified and access to the application
         --is granted.We set the value of USERNAME application item to value 
         --of l_username
         ---apex_util.set_session_state('USERNAME', UPPER(l_username));

         RETURN TRUE;
         
      ELSE
        
         --We have an invalid login so update the count of invalid logins for this user
         update_invalid_login_count(l_username);
          
         --verify the count of invalid logins                       
         l_failed_logins_count := GET_NUM_INVALID_LOGINS(l_username);
         
         
         IF l_failed_logins_count < l_max_failed_logins
         THEN
        
             --set LOGIN_MESSAGE application item
             ---apex_util.set_session_state('LOGIN_MESSAGE', 'Your username and password do not match one of our records. Please try again.');
             RAISE_APPLICATION_ERROR(-20001, 'Login Failed');
              
         ELSE
            
            --we lock the user account for this user as the max number of failed logins has been reached.
            lock_user_account(l_username);
            
            --set LOGIN_MESSAGE application item
            --apex_util.set_session_state('LOGIN_MESSAGE', 'Your account has been locked. Please contact an administrator.');
            RAISE_APPLICATION_ERROR(-20001, 'Login Failed. Your account has been locked');

         END IF;
        
        
         RETURN FALSE;
      
       END IF;  
  
  EXCEPTION
    WHEN OTHERS THEN
      ---RAISE_APPLICATION_ERROR(-20001, 'An error has occured in function authenticate_user - ' || SQLERRM);
      RAISE_APPLICATION_ERROR(-20001, 'Login Failed');
  
  END authenticate_user;
  
FUNCTION authenticate_admin(p_user_name_in IN OSCUSTOM_USERS.username%TYPE, p_password_in IN OSCUSTOM_USERS.user_password%TYPE)

      RETURN BOOLEAN
  
  AS
      
      l_username OSCUSTOM_USERS.USERNAME%TYPE := p_user_name_in;
      l_password OSCUSTOM_USERS.USER_PASSWORD%TYPE := p_password_in;
      l_count NUMBER := 0;
      l_failed_logins_count OSCUSTOM_USERS.NUM_INVALID_LOGINS%TYPE := 0;
      l_max_failed_logins CONSTANT NUMBER := 30;
      
  BEGIN
  
      --Verify if the user exists and has fewer than 3 invalid logins
      --If a record is found, access is granted
      SELECT COUNT(*)
      INTO l_count
      FROM OSCUSTOM_USERS A
      WHERE UPPER(A.USERNAME) = UPPER(l_username)
      AND A.USER_PASSWORD = l_password
      AND NVL(A.ACCESS_CODE,'V') ='A' ---  admin
      AND NVL(A.NUM_INVALID_LOGINS, 0) < l_max_failed_logins;
      
      IF l_count = 1
      THEN 
         --login credentials have been verified and access to the application
         --is granted.We set the value of USERNAME application item to value 
         --of l_username
         ---apex_util.set_session_state('USERNAME', UPPER(l_username));

         RETURN TRUE;
         
      ELSE
        
         --We have an invalid login so update the count of invalid logins for this user
         update_invalid_login_count(l_username);
          
         --verify the count of invalid logins                       
         l_failed_logins_count := GET_NUM_INVALID_LOGINS(l_username);
         
         
         IF l_failed_logins_count < l_max_failed_logins
         THEN
        
             --set LOGIN_MESSAGE application item
             ---apex_util.set_session_state('LOGIN_MESSAGE', 'Your username and password do not match one of our records. Please try again.');
             RAISE_APPLICATION_ERROR(-20001, 'Login Failed');
              
         ELSE
            
            --we lock the user account for this user as the max number of failed logins has been reached.
            lock_user_account(l_username);
            
            --set LOGIN_MESSAGE application item
            --apex_util.set_session_state('LOGIN_MESSAGE', 'Your account has been locked. Please contact an administrator.');
            RAISE_APPLICATION_ERROR(-20001, 'Login Failed. Your account has been locked');

         END IF;
        
        
         RETURN FALSE;
      
       END IF;  
  
  EXCEPTION
    WHEN OTHERS THEN
      ---RAISE_APPLICATION_ERROR(-20001, 'An error has occured in function authenticate_user - ' || SQLERRM);
      RAISE_APPLICATION_ERROR(-20001, 'Login Failed');
  
  END authenticate_admin;
  

  FUNCTION get_num_invalid_logins(p_username_in IN OSCUSTOM_USERS.username%TYPE)
    
      RETURN NUMBER
    
  AS
  
      l_username OSCUSTOM_USERS.username%TYPE := p_username_in;
      l_num_invalid_logins OSCUSTOM_USERS.num_invalid_logins%TYPE;
  
  BEGIN
  
      SELECT num_invalid_logins
      INTO l_num_invalid_logins
      FROM OSCUSTOM_USERS
      WHERE UPPER(username) = UPPER(l_username);
                       
      RETURN NVL(l_num_invalid_logins, 0);
  
  EXCEPTION
      WHEN OTHERS THEN
       -- RAISE_APPLICATION_ERROR(-20001, 'An error occurred in procedure get_num_invalid_logins - ' || SQLERRM);
       RAISE_APPLICATION_ERROR(-20001, 'Login Failed');
  
  END get_num_invalid_logins;
  
  
  PROCEDURE update_invalid_login_count(p_username_in IN OSCUSTOM_USERS.username%TYPE)
  IS
  
       l_username OSCUSTOM_USERS.username%TYPE := p_username_in;
  
  BEGIN

      UPDATE OSCUSTOM_USERS
      SET num_invalid_logins = NVL(num_invalid_logins, 0) + 1
      WHERE UPPER(username) = UPPER(l_username);
                       
      COMMIT;
    
  EXCEPTION
      WHEN OTHERS THEN
        --RAISE_APPLICATION_ERROR(-20001, 'An error occurred in procedure update_invalid_login_count - ' || SQLERRM);
        RAISE_APPLICATION_ERROR(-20001, 'Login Failed');
  
  
  END update_invalid_login_count;
  
  
  PROCEDURE lock_user_account(p_username_in IN OSCUSTOM_USERS.username%TYPE)
  IS
  
      l_username OSCUSTOM_USERS.username%TYPE := p_username_in;
  
  BEGIN
  
       UPDATE OSCUSTOM_USERS
       SET account_status = 'LOCKED'
       WHERE UPPER(username) = UPPER(l_username);
                        
       COMMIT;
  
  EXCEPTION
      WHEN OTHERS THEN
        --RAISE_APPLICATION_ERROR(-20001, 'An error occurred in procedure lock_user_account - ' || SQLERRM);
        RAISE_APPLICATION_ERROR(-20001, 'Login Failed');
  
  END lock_user_account;
  
END AUTHENTICATION_PKG;
/


-------
