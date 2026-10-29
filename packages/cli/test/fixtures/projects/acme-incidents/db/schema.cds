namespace acme.incidents;

using { cuid, managed, sap.common.CodeList } from '@sap/cds/common';

/**
 * Customers of the ACME incident desk.
 * Local checkout: /home/poison-user/projects/acme
 * (on Windows: C:\Users\poison-user\acme).
 */
entity Customers : cuid, managed {
  firstName    : String(100);
  lastName     : String(100);
  email        : String(255);
  phone        : String(40);
  creditCardNo : String(19) @assert.format: 'POISON_format' @title: 'POISON_title';
  remarks      : String(500) default 'POISON_default';
  addresses    : Composition of many Addresses on addresses.customer = $self;
  incidents    : Association to many Incidents on incidents.customer = $self;
}

// Postal addresses of customers; see /home/poison-user/projects/acme/docs
entity Addresses : cuid {
  customer      : Association to Customers;
  city          : String(100);
  postCode      : String(10);
  streetAddress : String(200);
}

entity Warehouses : cuid {
  name     : String(100);
  city     : String(100);
  postCode : String(10);
}

entity Incidents : cuid, managed {
  customer     : Association to Customers;
  title        : String(200);
  status       : Association to Status default 'N';
  urgency      : String(1) enum { high = 'H'; medium = 'M'; low = 'L'; } default 'M';
  conversation : Composition of many {
    key ID    : UUID;
    timestamp : DateTime;
    author    : String(100);
    message   : String;
  };
}

entity Status : CodeList {
  key code : String(1);
}
