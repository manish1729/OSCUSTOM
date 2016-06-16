CREATE OR REPLACE PROCEDURE  UPLOAD_LSC_FILE AS
   l_count     number;
   l_JSONTEXT	CLOB;

CURSOR LSCFILES IS
SELECT file_name 
from files_vxt;
   
   BEGIN 
   
   for filelist in LSCFILES
   LOOP
   		READ_LSC_FILE('LSC_IN',FILELIST.FILE_NAME);
   		DBMS_OUTPUT.PUT_LINE ( filelist.file_name);
   		
   		
   		--- MOVE THE FILE TO ARCHIVE FOLDER
   		
   		 UTL_FILE.FRENAME (
		    src_location  => 'LSC_IN',
		    src_filename  => FILELIST.FILE_NAME, 
		    dest_location => 'LSC_ARCHIVE',
		    dest_filename => 'P_'||FILELIST.FILE_NAME,
    overwrite     => FALSE);
   
   
   END LOOP;
    
    END;