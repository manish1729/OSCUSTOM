CREATE TABLE OSCUSTOM_SHIPPING_DATA
(
  ID NUMBER NOT NULL 
, ACTUAL_SHIP_DATE VARCHAR2(30 BYTE) 
, SHIP_TO_COUNTRY_NAME VARCHAR2(30 BYTE) 
, SOLD_TO_CUSTOMER_NAME VARCHAR2(30 BYTE) 
, SHIP_TO_CUSTOMER_NAME VARCHAR2(255 BYTE) 
, CUSTOMER_PURCHASE_ORDER_NUMBER VARCHAR2(30 BYTE) 
, PRODUCT_ID VARCHAR2(30 BYTE) 
, MACHINE_MODEL_DESCRIPTION VARCHAR2(30 BYTE) 
, SERIAL_NUMBER VARCHAR2(30 BYTE) 
, MAC_ADDRESSES VARCHAR2(30 BYTE) 
, ASSET_TAG VARCHAR2(30 BYTE) 
, PRODUCT_DESCRIPTION VARCHAR2(30 BYTE) 
, PRODUCT_BRAND_DESCRIPTION VARCHAR2(30 BYTE) 
, ORDER_QUANTITY NUMBER 
, SHIPPED_QUANTITY NUMBER 
, ORDER_RECEIPT_DATE DATE 
, ESTIMATED_DELIVERY_DATE DATE 
, ACTUAL_DELIVERY_DATE DATE 
, CARRIER_TRACKING_NUMBER NUMBER 
, ORDER_STATUS VARCHAR2(30 BYTE) 
, INVOICE_NUMBER NUMBER 
, SOLD_TO_CUSTOMER_NUMBER NUMBER 
, SHIP_TO_STREET_1 VARCHAR2(255 BYTE) 
, SHIP_TO_STREET_2 VARCHAR2(255 BYTE) 
, SHIP_TO_POSTAL_CODE NUMBER 
, SHIP_TO_CITY VARCHAR2(30 BYTE) 
, GLOBAL_LOCATION_NUMBER VARCHAR2(30 BYTE) 
, SALES_ORDER_NUMBER NUMBER 
, LINE_ITEM_STATUS VARCHAR2(30 BYTE) 
, GEOGRAPHY_IDENTIFIER VARCHAR2(30 BYTE) 
, DIRECT_OR_INDIRECT VARCHAR2(30 BYTE) 
, CLIENT_ID VARCHAR2(30)
, CONSTRAINT OSCUSTOM_SHIPTEST_PK PRIMARY KEY 
  (
    ID 
  )
  USING INDEX 
  (
      CREATE UNIQUE INDEX OSCUSTOM_SHIPPING_DATA_PK ON OSCUSTOM_SHIPPING_DATA (ID ASC) 
      LOGGING 
      TABLESPACE APEX_5718720848393858 
      PCTFREE 10 
      INITRANS 2 
      STORAGE 
      ( 
        INITIAL 65536 
        NEXT 1048576 
        MINEXTENTS 1 
        MAXEXTENTS UNLIMITED 
        BUFFER_POOL DEFAULT 
      ) 
      NOPARALLEL 
  )
  ENABLE 
) 
LOGGING 
TABLESPACE APEX_5718720848393858 
PCTFREE 10 
INITRANS 1 
STORAGE 
( 
  INITIAL 65536 
  NEXT 1048576 
  MINEXTENTS 1 
  MAXEXTENTS UNLIMITED 
  BUFFER_POOL DEFAULT 
) 
NOPARALLEL;

create sequence OSCUSTOM_SHIPPING_DATA_SEQ;

CREATE OR REPLACE TRIGGER OSCUSTOM_SHIPPING_DATA_TRG
  BEFORE INSERT 
  ON OSCUSTOM_SHIPPING_DATA
  FOR EACH ROW
  BEGIN
  
  SELECT OSCUSTOM_SHIPPING_DATA_SEQ.nextval
    INTO   :new.id
  FROM   dual;
    
END;