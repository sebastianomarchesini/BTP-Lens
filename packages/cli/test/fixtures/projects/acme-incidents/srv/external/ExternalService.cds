/* Imported from an external OData service; no local endpoint. */
@cds.external
service ExternalService {
  entity Suppliers {
    key ID   : String(10);
        name : String(100);
  }
}
