from django.contrib.auth import authenticate, logout, login
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.hashers import make_password
from django.core.urlresolvers import reverse
from django.db.models import Q
from django.shortcuts import HttpResponseRedirect
from django.shortcuts import render
from django.views import View

from users.forms import LoginForm, RegisterForm, ForgetPwdForm, ModifyPwdForm, ChangePwdForm, UploadImageForm
from users.models import UserInfo, EmailVerify
from utils.email_send import send_register_email
from utils.mixin_utils import LoginRequiredMixin


class CustomBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = UserInfo.objects.get(Q(username=username) | Q(email=username))
            if user.check_password(password):
                return user
        except Exception as e:
            return None


class IndexView(View):
    def get(self, request):
        return render(request,'index.htm', {})


class LoginView(View):
    def get(self, request):
        return render(request, 'login.html', {})

    def post(self, request):
        login_form = LoginForm(request.POST)
        if login_form.is_valid():
            user_name = request.POST.get("username", "")
            pass_word = request.POST.get("password", "")
            user = authenticate(username=user_name, password=pass_word)
            if user is not None:
                login(request,user)
                return HttpResponseRedirect(reverse("index"))
            else:
                return render(request, "login.html", {'msg': '账号密码有误'})
        else:
            return render(request, "login.html", {'login_form':login_form})


class LogoutView(View):
    def get(self, request):
        logout(request)
        return render(request, 'index.htm', {})


class RegisterView(View):
    def get(self, request):
        register_form = RegisterForm()
        return render(request, 'register.html', {'register_form': register_form})

    def post(self, request):
        # 获取前段的数据
        register_form = RegisterForm(request.POST)
        # 验证表单是不是合法
        if register_form.is_valid():
            email = request.POST.get("email", "")
            if UserInfo.objects.filter(email=email):
                return render(request, "register.html", {
                    "register_form": register_form,
                    "msg": "用户已经存在!"})

            pass_word = request.POST.get("password", "")

            #  实例化UserProfile字段
            user_profile = UserInfo()
            user_profile.username = email
            user_profile.email = email
            user_profile.is_active = False
            user_profile.password = make_password(pass_word)

            user_profile.save()

            # 发送邮箱
            send_register_email(email, 'register')

            return HttpResponseRedirect(reverse("login"))
        else:
            return render(request, "register.html", {"register_form": register_form})


class ActiveUserView(View):
    def get(self, request, active_code):
        all_records = EmailVerify.objects.filter(code=active_code)
        if all_records:
            for record in all_records:
                email = record.email
                user = UserInfo.objects.get(email=email)
                user.is_active = True
                user.save()
                return render(request, 'success_activate.html')
            return render(request, 'login.html')


class ForgetPwdView(View):
    def get(self, request):
        forget_from = ForgetPwdForm()
        return render(request, 'forgetpwd.html', {'forget_from': forget_from})

    def post(self, request):
        forget_from = ForgetPwdForm(request.POST)
        if forget_from.is_valid():
            email = request.POST.get("email", "")
            if UserInfo.objects.filter(email=email):
                send_register_email(email, 'forget')
                return render(request, 'send_success.html', {'email': email})

            return render(request, 'forgetpwd.html', {'msg': u"用户不存在!!",
                                                      'forget_from': forget_from})
        else:
            return render(request, 'forgetpwd.html', {'forget_from': forget_from})


class ResetView(View):
    def get(self, request, reset_code):
        all_records = EmailVerify.objects.filter(code=reset_code)
        if all_records:
            for record in all_records:
                email = record.email
                return render(request, "password_reset.html", {"email": email})


class ModifyPwdView(View):
    def post(self, request):
        modify_form = ModifyPwdForm(request.POST)
        if modify_form.is_valid():
            pwd1 = request.POST.get("password1", "")
            pwd2 = request.POST.get("password2", "")
            email = request.POST.get("email", "")
            if pwd1 != pwd2:
                return render(request, "password_reset.html", {"email": email, "msg": "密码不一致"})
            user = UserInfo.objects.get(email=email)
            user.password = make_password(pwd2)
            user.save()
            return render(request, 'reset_success.html')
        else:
            email = request.POST.get("email", "")
            return render(request, "password_reset.html", {"email": email, "modify_form": modify_form})


class UserInfoView(LoginRequiredMixin, View):
    def get(self, request):
        return render(request, 'my_info.html', {})

    # def post(self, request):
    #     info_form = UploadInfoForm(request.POST, instance=request.user)
    #     if info_form.is_valid():
    #         info_form.save()
    #         return HttpResponseRedirect(reverse("i:info"))
    #     else:
    #         return render(request, 'my_info.html', {'info_form': info_form})


class ChangePwdView(LoginRequiredMixin, View):
    def get(self, request):
        email = request.user.email
        return render(request, 'my_paasword.html', {'email': email})

    def post(self, request):
        change_form = ChangePwdForm(request.POST)
        email = request.user.email
        if change_form.is_valid():
            pwdold = request.POST.get("passwordold", "")
            email = request.POST.get("email", "")
            user = authenticate(username=email, password=pwdold)
            if user is not None:
                pwd1 = request.POST.get("password1", "")
                pwd2 = request.POST.get("password2", "")
                if pwd1 != pwd2:
                    return render(request, "my_paasword.html", {"email": email, "msg": u"密码不一致"})
                user = UserInfo.objects.get(email=email)
                user.password = make_password(pwd2)
                user.save()

                return render(request, 'reset_success.html')
            else:
                return render(request, "my_paasword.html", {"email": email, "msg": u"旧密码不对"})

        return render(request, 'my_paasword.html', {'change_form': change_form, 'email': email})


# 用户订单
class UserOrderView(LoginRequiredMixin, View):
    def get(self, request):
        return render(request, 'my_order.html', {})

    def post(self, request):
        pass


# 用户作业
class UserWorkView(LoginRequiredMixin, View):
    def get(self, request):
        return render(request, 'my_homework.html', {})

    def post(self, request):
        pass


# 用户课程
class UserCourseView(LoginRequiredMixin, View):
    def get(self, request):
        return render(request, 'my_course.html', {})

    def post(self, request):
        pass


# 用户修改头像
class UploadImageView(LoginRequiredMixin, View):

    # def post(self, request):
    #     # 把前段传入的数据保存    直接实例化,实例化直接保存
    #     image_form = UploadImageForm(request.POST, request.FILES, instance=request.user)
    #     print(dir(image_form))
    #     if image_form.is_valid():
    #         image_form.save()
    #         return HttpResponseRedirect(reverse("i:info"))
    #     else:
    #         return render(request, 'my_info.html')

    # 常规方式
    def post(self, request):

        image_form = UploadImageForm(request.POST, request.FILES)
        if image_form.is_valid():

            image = image_form.cleaned_data['image']
            request.user.image = image
            request.user.save()
            return HttpResponseRedirect(reverse("i:info"))
        else:
            return render(request, 'my_info.html')
