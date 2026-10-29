namespace clean.cap;

using { cuid, managed } from '@sap/cds/common';

@PersonalData.EntitySemantics: 'DataSubject'
entity Customers : cuid, managed {
  @PersonalData.FieldSemantics: 'DataSubjectID'
  email     : String(255);
  @PersonalData.IsPotentiallyPersonal
  firstName : String(100);
  @PersonalData.IsPotentiallyPersonal
  lastName  : String(100);
  contacts  : Composition of many Contacts on contacts.customer = $self;
}

entity Contacts : cuid {
  customer : Association to Customers;
  phone    : String(40);
  city     : String(100);
}

entity Products : cuid {
  name  : String(100);
  price : Decimal(9, 2);
}
