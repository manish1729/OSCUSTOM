CREATE OR REPLACE PROCEDURE  PROCESS_LSC_FILE AS
   l_count     number;
   l_JSONTEXT	CLOB;
   L_CONFIG_SEQ	NUMBER;
   L_LEVEL1	VARCHAR2(100);
   L_LEVEL2	VARCHAR2(100);
   L_LEVEL3	VARCHAR2(100);
   L_LEVEL	NUMBER;
   
   L_L1_ARRY	CHAR(1):='Y';
   L_L2_ARRY	CHAR(1):='Y';
   L_L3_ARRY	CHAR(1):='Y';
   
   L_PATH	VARCHAR2(100);
   L_L1_PATH	VARCHAR2(100);
   L_L2_PATH	VARCHAR2(100);
   l_final_property_path	VARCHAR2(100);
   
   L_L1_CNT	NUMBER;
   L_L2_CNT	NUMBER;
   l_propertycount number;
   
   l_deviceid	VARCHAR2(100);
   l_devicetypename	VARCHAR2(100);
   l_basevalue	VARCHAR2(100);
   l_CurrentValue	VARCHAR2(100);
   l_IsDifferent	VARCHAR2(100);
   l_PropertyName	VARCHAR2(100);
   
   L_DATEOFCREATION 	VARCHAR2(100);
   
   L_FILENAME		VARCHAR2(100);
   L_MACHINEID		VARCHAR2(100);
   L_SERIALNUMBER	VARCHAR2(100);
   
   L_ERRCODE		NUMBER;
   L_ERRMSG		VARCHAR2(100);
    
   

CURSOR LSCFILES IS
SELECT * from FLTB_UPLOAD_MASTER
WHERE PROCESS_STATUS='U';

CURSOR LSC_MASTER IS
SELECT * FROM CFTM_LSC_MASTER;
   
   BEGIN 
   
   for LSC_REC in LSCFILES
   LOOP
   		--- Initialize all the variables
   
   BEGIN
   		
   		  l_count :=0;
		   
		   L_CONFIG_SEQ	:=0;
		   L_LEVEL1	:=NULL;
		   L_LEVEL2	:=NULL;
		   L_LEVEL3	:=NULL;
		   L_LEVEL	:=0;
		   
		   L_L1_ARRY	:='Y';
		   L_L2_ARRY	:='Y';
		   L_L3_ARRY	:='Y';
		   
		   L_PATH	:=NULL;
		   L_L2_PATH	:=NULL;
		   L_L1_PATH	:=NULL;
		   l_final_property_path	:=NULL;
		   
		   L_L1_CNT	:=0;
		   L_L2_CNT	:=0;
		   l_propertycount :=0;
		   
		   l_deviceid	:=NULL;
		   l_devicetypename	:=NULL;
		   l_basevalue	:=NULL;
		   l_CurrentValue	:=NULL;
		   l_IsDifferent	:=NULL;
   			l_PropertyName	:=NULL;
   		
   		--- Initialize all the variables end
   		
   		
   		L_FILENAME:=LSC_REC.FILENAME;
   		L_MACHINEID:=LSC_REC.FILENAME;
   		L_SERIALNUMBER:=LSC_REC.FILENAME;
   		
   		/*
   		logic is required to derive machine id and serial number from filename.
   		*/
   		
   		l_JSONTEXT:=LSC_REC.JSONTEXT;
   		APEX_JSON.parse(l_JSONTEXT);
   
   		L_DATEOFCREATION:=APEX_JSON.get_varchar2(p_path => 'DateOfCreation');
   		DBMS_OUTPUT.put_line ('DATE OF CREATION 1:='||L_DATEOFCREATION);
   
   		FOR LSC_CONFIG IN LSC_MASTER
   		LOOP
   				L_CONFIG_SEQ:=LSC_CONFIG.CONTROL_SEQNO;
   				L_LEVEL1:=LSC_CONFIG.PROPERTY_LEVEL1;
   				L_LEVEL2:=LSC_CONFIG.PROPERTY_LEVEL2;
   				L_LEVEL3:=LSC_CONFIG.PROPERTY_LEVEL3;
   				DBMS_OUTPUT.put_line(LSC_CONFIG.PROPERTY_LEVEL1); 
   				DBMS_OUTPUT.put_line(LSC_CONFIG.PROPERTY_LEVEL2);
   				DBMS_OUTPUT.put_line(LSC_CONFIG.PROPERTY_LEVEL3);
   				L_LEVEL:=0;
   				IF L_LEVEL1 IS NOT NULL 
   				THEN
   					L_LEVEL:=L_LEVEL+1;
   				END IF;
   				IF L_LEVEL2 IS NOT NULL 
				THEN
					L_LEVEL:=L_LEVEL+1;
   				END IF;
   				IF L_LEVEL3 IS NOT NULL 
				THEN
					L_LEVEL:=L_LEVEL+1;
   				END IF;
   				
   				
   				DBMS_OUTPUT.put_line ('PROPERTY 1:='||L_LEVEL1);
   				DBMS_OUTPUT.put_line ('PROPERTY 2:='||L_LEVEL2);
   				DBMS_OUTPUT.put_line ('PROPERTY 3:='||L_LEVEL3);
   				DBMS_OUTPUT.put_line ('PROPERTY LEVEL:='||L_LEVEL);
   				
   				IF L_LEVEL=1
   				THEN
   							L_L1_CNT:=APEX_JSON.get_count(p_path =>l_level1 );
   							
   							IF  APEX_JSON.DOES_EXIST(P_PATH=>L_LEVEL1||'[1]') THEN
   								L_L1_ARRY:='Y';
   								
   								L_L1_PATH :=L_LEVEL1||'[REPL_L1].';
   								
   							ELSE
   								L_L1_ARRY :='N';
   								L_L1_CNT:=1;	--- JSON OBJECT SHOULD HAVE ONLY 1 LOOP
   								L_L1_PATH :=L_LEVEL1||'.';
   							END IF;
   						
   						

						    DBMS_OUTPUT.put_line('LEVEL1 Count   : ' || L_L1_CNT);
						    
						    						    
						

						DBMS_OUTPUT.put_line('path-->'||L_PATH);
						  for l1 in 1..L_L1_CNT
						  loop
								
								L_PATH:=REPLACE(L_L1_PATH,'REPL_L1',l1);
								
								DBMS_OUTPUT.put_line('L_PATH L1 : ' || L_PATH);
								
								
								DBMS_OUTPUT.put_line(L_PATH||'DeviceId');
								l_deviceid:= APEX_JSON.get_varchar2(p_path => L_PATH||'DeviceId'); 
								
								DBMS_OUTPUT.put_line(L_PATH||'DeviceTypeName');
								l_devicetypename:= APEX_JSON.get_varchar2(p_path => L_PATH||'DeviceTypeName');
								

								l_propertycount :=APEX_JSON.get_count(p_path =>L_PATH||'Properties' );

								DBMS_OUTPUT.put_line('Properties ='||l_propertycount);

								for j in 1..l_propertycount
								loop
										l_final_property_path:=L_PATH||'Properties['||j||'].';

									l_basevalue:=APEX_JSON.get_varchar2(p_path => l_final_property_path||'BaseValue');
									l_CurrentValue:=APEX_JSON.get_varchar2(p_path => l_final_property_path||'CurrentValue');
									l_IsDifferent:=APEX_JSON.get_varchar2(p_path => l_final_property_path||'IsDifferent');
									l_PropertyName:=APEX_JSON.get_varchar2(p_path => l_final_property_path||'PropertyName');

										-- DBMS_OUTPUT.put_line(L_LEVEL1);
										 DBMS_OUTPUT.put_line(l_final_property_path);
										 DBMS_OUTPUT.put_line(j);
										-- DBMS_OUTPUT.put_line(l_deviceid);
										-- DBMS_OUTPUT.put_line(l_devicetypename);
										-- DBMS_OUTPUT.put_line(l_basevalue); 
										-- DBMS_OUTPUT.put_line(l_CurrentValue); 
										-- DBMS_OUTPUT.put_line(l_IsDifferent); 
										-- DBMS_OUTPUT.put_line(l_PropertyName); 
										 
										 INSERT INTO CFTB_LSC_PROPERTIES
										 (
										 PROPERTY_SEQ_NO,
										   MACHINE_ID,
										   SERIAL_NUMBER,
										   CREATION_DATE,
										   PROCESSING_DATE,
										   LSC_SEQ,
										   PROPERTY_LEVEL1,
										   DEVICEID,
										   DEVICETYPENAME,
										   BASEVALUE,
										   CURRENTVALUE,
										   ISDIFFERENT,
 										   PROPERTYNAME
 										  )
 										  VALUES
 										  (
 										  PROPERTY_SEQ_NO.NEXTVAL,
 										  L_MACHINEID,
 										  L_SERIALNUMBER,
 										  L_DATEOFCREATION,
 										  SYSDATE,
 										  LSC_CONFIG.CONTROL_SEQNO,
 										  LSC_CONFIG.PROPERTY_LEVEL1,
 										  l_deviceid,
 										  l_devicetypename,
 										  l_basevalue,
 										  l_CurrentValue,
 										  l_IsDifferent,
 										  l_PropertyName
 										  );
										 
										 

									
										 

								end loop;



						  end loop;
						  
				ELSIF L_LEVEL=2
   				THEN
					
					L_L1_CNT:=APEX_JSON.get_count(p_path =>l_level1 );
					
					
					IF  APEX_JSON.DOES_EXIST(P_PATH=>L_LEVEL1||'[1]') THEN
						L_L1_ARRY:='Y';

						L_L1_PATH :=L_LEVEL1||'[REPL_L1].';

					ELSE
						L_L1_ARRY :='N';
						L_L1_CNT:=1;	--- JSON OBJECT SHOULD HAVE ONLY 1 LOOP
						L_L1_PATH :=L_LEVEL1||'.';
					END IF;
					
				
					DBMS_OUTPUT.put_line('path 2-->'||L_PATH);
					  for l1 in 1..L_L1_CNT
					  loop
					  
					  		L_PATH:=REPLACE(L_L1_PATH,'REPL_L1',l1);
															
							DBMS_OUTPUT.put_line('L_PATH L1 : ' || L_PATH);
						
							
							-- LEVEL 2 : NEED TO DO EXCATLY SAME CHECK AS LEVEL1
							IF  APEX_JSON.DOES_EXIST(P_PATH=>L_PATH||l_level2||'[1]') THEN
								L_L2_ARRY:='Y';
								L_L2_CNT:=APEX_JSON.get_count(p_path =>L_PATH||l_level2 );
								L_L2_PATH :=L_PATH||l_level2||'[REPL_L2].';
							ELSE
								L_L2_ARRY :='N';
								L_L2_CNT:=1;
								L_L2_PATH :=L_PATH||l_level2||'.';
							END IF;
												
								FOR L2 IN 1..L_L2_CNT
								LOOP
									
									L_PATH:=REPLACE(L_L2_PATH,'REPL_L2',l2);
									
									
									DBMS_OUTPUT.put_line(L_PATH||'DeviceId');
									l_deviceid:= APEX_JSON.get_varchar2(p_path => L_PATH||'DeviceId'); 

									DBMS_OUTPUT.put_line(L_PATH||'DeviceTypeName');
									l_devicetypename:= APEX_JSON.get_varchar2(p_path => L_PATH||'DeviceTypeName');


									l_propertycount :=APEX_JSON.get_count(p_path =>L_PATH||'Properties' );

									DBMS_OUTPUT.put_line('Properties ='||l_propertycount);

									for j in 1..l_propertycount
									loop
											l_final_property_path:=L_PATH||'Properties['||j||'].';

										l_basevalue:=APEX_JSON.get_varchar2(p_path => l_final_property_path||'BaseValue');
										l_CurrentValue:=APEX_JSON.get_varchar2(p_path => l_final_property_path||'CurrentValue');
										l_IsDifferent:=APEX_JSON.get_varchar2(p_path => l_final_property_path||'IsDifferent');
										l_PropertyName:=APEX_JSON.get_varchar2(p_path => l_final_property_path||'PropertyName');

											-- DBMS_OUTPUT.put_line(L_LEVEL1);
											 DBMS_OUTPUT.put_line(l_final_property_path);
											  DBMS_OUTPUT.put_line(j);
											-- DBMS_OUTPUT.put_line(l_deviceid);
											-- DBMS_OUTPUT.put_line(l_devicetypename);
											-- DBMS_OUTPUT.put_line(l_basevalue); 
											-- DBMS_OUTPUT.put_line(l_CurrentValue); 
											-- DBMS_OUTPUT.put_line(l_IsDifferent); 
											-- DBMS_OUTPUT.put_line(l_PropertyName); 
											 
											 
											  INSERT INTO CFTB_LSC_PROPERTIES
												 (
												 PROPERTY_SEQ_NO,
												   MACHINE_ID,
												   SERIAL_NUMBER,
												   CREATION_DATE,
												   PROCESSING_DATE,
												   LSC_SEQ,
												   PROPERTY_LEVEL1,
												   DEVICEID,
												   DEVICETYPENAME,
												   BASEVALUE,
												   CURRENTVALUE,
												   ISDIFFERENT,
												   PROPERTYNAME
												  )
												  VALUES
												  (
												  PROPERTY_SEQ_NO.NEXTVAL,
												  L_MACHINEID,
												  L_SERIALNUMBER,
												  L_DATEOFCREATION,
												  SYSDATE,
												  LSC_CONFIG.CONTROL_SEQNO,
												  LSC_CONFIG.PROPERTY_LEVEL1,
												  l_deviceid,
												  l_devicetypename,
												  l_basevalue,
												  l_CurrentValue,
												  l_IsDifferent,
												  l_PropertyName
												  );
										 
											 

									end loop;
								END LOOP;



					  end loop;
					  

 								
   				
   				END IF; -- levle if,1,2,3
   				 
   					
   		
   		END LOOP; -- LSCCONFIG;

 UPDATE FLTB_UPLOAD_MASTER
 SET PROCESS_STATUS='P'
 WHERE FILE_SEQNO=LSC_REC.FILE_SEQNO;
 
 ---COMMIT;
 
 EXCEPTION WHEN OTHERS
 THEN
 		---INSERT EXCEPTION
 		
 		ROLLBACK;
 		L_ERRCODE:=SQLCODE;
 		L_ERRMSG :=SUBSTR(SQLERRM, 1 , 100);
 		
 		INSERT INTO CFTB_LSC_PROPERTIES_EXCEPTION
		  ( 
		  PROPERTY_SEQ_NO,
		  MACHINE_ID,
		  SERIAL_NUMBER,
		  CREATION_DATE,
		  PROCESSING_DATE,
		  ERR_CODE,
  		  ERR_MSG
  		  )
  		  VALUES
  		  (
  		  PROPERTY_SEQ_NO.NEXTVAL,
		  L_MACHINEID,
		  L_SERIALNUMBER,
		  L_DATEOFCREATION,
		  SYSDATE,
		  L_ERRCODE,
		  L_ERRMSG
  		  );
  		  
 
 END;
 
 COMMIT;
   
   END LOOP; --- LSCFILES
    
    END;