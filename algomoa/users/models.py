from django.db import models

# Create your models here.
class User(models.Model):
    email = models.CharField(max_length = 50, null = True)
    user_id = models.CharField(max_length = 50, null = True)
    user_pwd = models.CharField(max_length = 400, null = True)
    name = models.CharField(max_length = 50)
    backjoon_id = models.CharField(max_length = 50, null = True)
    checked_social = models.BooleanField() # 소셜 로그인 여부에 따라 true or false
    user_created = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'users'
    
    def __str__(self):
        return self.email 