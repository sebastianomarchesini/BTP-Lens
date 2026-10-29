using { clean.cap as db } from '../db/schema';

service CatalogService @(requires: 'authenticated-user') {
  @restrict: [
    { grant: 'READ', to: 'viewer' },
    { grant: '*', to: 'admin' }
  ]
  entity Customers as projection on db.Customers;

  @restrict: [{ grant: '*', to: 'admin' }]
  entity Contacts as projection on db.Contacts;

  @readonly entity Products as projection on db.Products;

  @(requires: 'admin')
  action recalculatePrices();
}
