## mauth
__2012-11-28__

PEAR::Authと互換性があり、パスワード・ハッシュの保存にソルトを用いて安全性を高めたPHP用認証ライブラリです。

## インストール

mauth.phpを適当なライブラリに保存してください。

初回にブラウザからsetup.phpを開き、CREATE TABLEのボタンを押してSQLiteによるDBを生成することができます。

## PEAR::Authとの互換性について

PEAR::Authのチュートリアルに記載されているサンプルをrequire_onceおよび$optionsを書き換えるだけで動作させることが可能です。

http://pear.php.net/manual/en/package.authentication.auth.intro.php

ただし、作者がよく使う関数から順に実装しており、サポートしていない関数もありますので、ご了承ください。
