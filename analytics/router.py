"""
Database router for the analytics app.

All analytics models live in a separate database ('analytics' alias,
kubepanel_analytics schema in the shared MariaDB instance) so that
high-volume raw request inserts are isolated from the panel's
operational tables.

Analytics models reference domains by domain_name (string), never by
foreign key - cross-database relations are not supported by Django.
"""


class AnalyticsRouter:
    """Route all models of the 'analytics' app to the analytics database."""

    app_label = 'analytics'
    db_alias = 'analytics'

    def db_for_read(self, model, **hints):
        if model._meta.app_label == self.app_label:
            return self.db_alias
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label == self.app_label:
            return self.db_alias
        return None

    def allow_relation(self, obj1, obj2, **hints):
        # Relations only within the same app (both analytics or both not)
        if (obj1._meta.app_label == self.app_label) != (obj2._meta.app_label == self.app_label):
            return False
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label == self.app_label:
            return db == self.db_alias
        # Keep every other app out of the analytics database
        if db == self.db_alias:
            return False
        return None
