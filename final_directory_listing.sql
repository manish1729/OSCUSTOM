To begin, we will create a simple example of a preprocessor directory listing and for this we require the following components:

    a read-write Oracle directory (for the external table);
    an executable Oracle directory (for the preprocessor);
    an external table;
    a shell/batch script;
    a dummy text file (for our table location).

As a SYSDBA, we will create the Oracle directories and grant the relevant privileges to SCOTT, as follows.

SQL> conn / as sysdba

Connected.

SQL> CREATE DIRECTORY xt_dir AS 'C:\JSONFILES\xt_dir';

Directory created.

SQL> GRANT READ, WRITE ON DIRECTORY xt_dir TO manish;

Grant succeeded.

SQL> CREATE DIRECTORY bin_dir AS 'C:\JSONFILES\bin_dir';

Directory created.

SQL> GRANT READ, WRITE ON DIRECTORY bin_dir TO manish;

GRANT READ, WRITE ON DIRECTORY bin_dir TO manish;

 GRANT EXECUTE ON DIRECTORY bin_dir TO manish;

Grant succeeded.



We will now create the external table to read a standard DOS directory listing, as follows.

SQL> conn manish/*****

Connected.

SQL> CREATE TABLE files_xt
  2  ( file_date VARCHAR2(50)
  3  , file_time VARCHAR2(50)
  4  , file_size VARCHAR2(50)
  5  , file_name VARCHAR2(255)
  6  )
  7  ORGANIZATION EXTERNAL
  8  (
  9    TYPE ORACLE_LOADER
 10    DEFAULT DIRECTORY xt_dir
 11    ACCESS PARAMETERS
 12    (
 13       RECORDS DELIMITED BY NEWLINE
 14       LOAD WHEN file_size != '<DIR>'
 15       PREPROCESSOR bin_dir: 'list_files.bat'
 16       FIELDS TERMINATED BY WHITESPACE
 17    )
 18    LOCATION ('sticky.txt')
 19  )
 20  REJECT LIMIT UNLIMITED;

Table created.

Note the following points about this external table:

    Line 14: we use the LOAD WHEN clause to exclude directories from our listings;
    Line 15: our preprocessor command simply calls a batch script named list_files.bat in the BIN_DIR;
    Line 18: we need a location clause, even though we are executing a script and not reading a file. This file must exist (even if it is not used) and cannot be a directory. Note that the file name given for the location can be read by the preprocessor batch script, so we will exploit this feature later on in this article to build a dynamic file listing. For now, however, we have no interest in the sticky.txt file other than its presence.

We now need to create two files; namely the preprocessor script (i.e. list_files.bat) and the location file (i.e. sticky.txt). As this is a Windows system, the preprocessor script needs to be a batch script. In our case, list_files.bat contains the following simple code:

create list_files.bat in bin_dir

@echo off
dir c:\manish



The first line is mandatory for batch scripts and the script itself must be located in the executable Oracle directory (in our case BIN_DIR). Note that for now we have hard-coded the directory we wish to query (i.e. the user dump destination for this instance).

Moving on, we can now create our sticky.txt location file in our Oracle read-write directory (XT_DIR), as follows.

create dummy file sticky.txt in xt_dir


SQL> host echo > C:\JSONFILES\xt_dir\sticky.txt

SQL> SELECT * FROM files_xt WHERE ROWNUM <= 5;

FILE_DATE    FILE_TIME    FILE_SIZE    FILE_NAME
------------ ------------ ------------ ----------------------
Volume       in           drive        D
Volume       Serial       Number       is
14/10/2009   22:39        618,508      alert_ora11.log
14/10/2009   22:38        1,474        ora11_cjq0_5148.trc
14/10/2009   22:38        175          ora11_cjq0_5148.trm




cleanup the above data using view .. this will eliminate Volume and directories


SQL> CREATE VIEW files_vxt
  2  AS
  3     SELECT file_name
  4     ,      TO_DATE(
  5               file_date||','||file_time,
  6               'DD/MM/YYYY HH24:MI') AS file_time
  7     ,      TO_NUMBER(
  8               file_size,
  9               'fm999,999,999,999') AS file_size
 10     FROM   files_xt
 11     WHERE  REGEXP_LIKE(
 12               file_date,
 13               '[0-9]{2}/[0-9]{2}/[0-9]{4}');

View created.



finally move the file to archive folder :



BEGIN
  UTL_FILE.FRENAME (
    src_location  => 'BIN_DIR',
    src_filename  => 'bin_file.txt', 
    dest_location => 'XT_DIR',
    dest_filename => 'filename.txt',
    overwrite     => FALSE);
END;
