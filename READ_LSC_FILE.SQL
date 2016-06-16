create or replace PROCEDURE  UPDATE_LSC_FILE(DIR IN VARCHAR2,FILE_NAME IN VARCHAR2) 
   IS acc_bal NUMBER(11,2);
   l_clob	CLOB;
   fil BFILE; 
         dst_offset  number := 1 ;
         src_offset  number := 1 ;
         lang_ctx    number := DBMS_LOB.DEFAULT_LANG_CTX;
       warning     number;

   
   BEGIN 
   
   	   fil:=BFILENAME(DIR,FILE_NAME);

	   INSERT INTO FLTB_UPLOAD_MASTER
		  (FILE_SEQNO,FILENAME,PROCESS_STATUS, JSONTEXT)
		   VALUES (  fileupload_seqno.NEXTVAL,FILE_NAME,'U', EMPTY_CLOB() )
		RETURNING JSONTEXT INTO l_clob;

	   dbms_lob.fileopen( fil, dbms_lob.FILE_READONLY );
	   DBMS_LOB.LOADCLOBFROMFILE(l_clob,fil,DBMS_LOB.LOBMAXSIZE,dst_offset,src_offset,DBMS_LOB.DEFAULT_CSID,lang_ctx,warning);
	    dbms_lob.close(fil); 

    
    END;