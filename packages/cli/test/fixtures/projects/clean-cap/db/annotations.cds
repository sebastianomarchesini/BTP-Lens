using { clean.cap as db } from './schema';

annotate db.Contacts with @PersonalData.EntitySemantics: 'DataSubjectDetails' {
  phone @PersonalData.IsPotentiallyPersonal;
  city  @PersonalData.IsPotentiallySensitive;
}
