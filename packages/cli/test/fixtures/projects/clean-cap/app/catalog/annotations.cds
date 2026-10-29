using BrowseService as service from '../../srv/catalog-service';

annotate service with @(requires: 'authenticated-user');

annotate service.Products with @(
    UI.HeaderInfo : {
        $Type : 'UI.HeaderInfoType',
        TypeName : 'Product',
        TypeNamePlural : 'Products',
    },
);
