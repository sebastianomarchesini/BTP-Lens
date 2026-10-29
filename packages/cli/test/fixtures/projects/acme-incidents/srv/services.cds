using { acme.incidents as db } from '../db/schema';

/** Full access for the incident desk administrators. */
service AdminService {
  entity Customers as projection on db.Customers;
  entity Incidents as projection on db.Incidents;
  function fetchCustomer(email : String) returns Customers;
}

service ProcessorService @(requires: 'support') {
  @restrict: [{ grant: 'READ', to: 'auditor', where: '$user.email = ''poison.where@example.com''' }]
  entity Incidents as projection on db.Incidents;
  @readonly entity Customers as projection on db.Customers;
}

service InternalService @protocol: 'none' {
  entity Warehouses as projection on db.Warehouses;
}

annotate AdminService.Incidents with @odata.draft.enabled;
