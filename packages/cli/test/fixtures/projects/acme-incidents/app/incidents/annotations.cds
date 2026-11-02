using AdminService as service from '../../srv/services';
using from '../../db/schema';

annotate service.Incidents with @(
    UI.HeaderInfo : {
        $Type : 'UI.HeaderInfoType',
        TypeName : 'POISON_ui',
        TypeNamePlural : 'POISON_ui_plural',
        Title : {
            $Type : 'UI.DataField',
            Value : title,
        },
    },
    UI.LineItem : [
        {
            $Type : 'UI.DataField',
            Value : title,
            Label : '{i18n>Title}',
        },
    ],
);
