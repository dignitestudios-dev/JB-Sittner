import React from 'react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import Login from '../pages/auth/login'
import ForgotPassword from '../pages/auth/forgotPassword'
import Otp from '../pages/auth/otp'
import UpdatePassword from '../pages/auth/updatePassword'
import Profile from '../pages/profile/Profile'
import EditProfile from '../pages/profile/EditProfile'
import Layout from '../global/Layout'
import TermsServices from '../pages/term/TermsServices'
import Privacy from '../pages/privacy/Privacy'
import Message from '../pages/messageBoard/Message'
import AddMember from '../pages/employee/AddMember'
import EditMember from '../pages/employee/EditMember'
import CreateLookAhead from '../pages/messageBoard/CreateLookAhead'
import EditLookAhead from '../pages/messageBoard/EditLookAhead'
import Schedule from '../pages/schedule/Schedule'
import CreateSchedule from '../pages/schedule/CreateSchedule'
import EditSchedule from '../pages/schedule/EditSchedulte'
import Notification from '../pages/notification/Notification'
import CreateNotification from '../pages/notification/CreateNotification'
import EditNotification from '../pages/notification/editNotification'
import Employee from '../pages/employee/Employee'
import AddAdmin from '../pages/admin/addAdmin'
import Admin from '../pages/admin/Admin'
import Cookie from '../pages/cookiepolicy/Cookie'

export default function AppRoutes() {
  return (
    <BrowserRouter>
    <Routes>
        {/* Auth */}
        <Route path='/login' element={<Login/>}/>
        <Route path='/forgotpassword' element={<ForgotPassword/>}/>
        <Route path='/otp' element={<Otp/>}/>
        <Route path='/updatepassword' element={<UpdatePassword/>}/>
        {/* Auth */}
        
        {/* Profile */}
        <Route path='/profile' element={ <Layout pages={<Profile/>} /> }/>
        <Route path='/editprofile' element={<Layout pages={<EditProfile/>} /> }/>
        {/* Profile */}
        
        <Route path='/term' element={<Layout pages={<TermsServices/>} /> }/>
        <Route path='/privacy' element={<Layout pages={<Privacy/>} /> }/>
        <Route path='/cookie' element={<Layout pages={<Cookie/>} />} />
   
         {/* Message */}
        <Route path='/' element={<Layout pages={<Message/>} /> }/>
        <Route path='/createlook' element={<Layout pages={<CreateLookAhead/>} /> }/>
        <Route path='/editlook' element={<Layout pages={<EditLookAhead/>} /> }/>
         {/* Message */}
         
         {/* Schedule */}
         <Route path='/schedule' element={<Layout pages={<Schedule/>} /> }/>
         <Route path='/createschedule' element={<Layout pages={<CreateSchedule/>} /> }/>
         <Route path='/editschedule' element={<Layout pages={<EditSchedule/>} /> }/>
         {/* Schedule */}
         
         {/* Notification */}
         <Route path='/notification' element={<Layout pages={<Notification/>} /> }/>
         <Route path='/createnotification' element={<Layout pages={<CreateNotification/>} /> }/>
         <Route path='/editnotification' element={<Layout pages={<EditNotification/>} /> }/>
         {/* Notification */}

         {/* Employee */}
         <Route path='/employee' element={<Layout pages={<Employee/>} /> }/>
         <Route path='/addmember' element={<Layout pages={<AddMember/>} /> }/>
         <Route path='/editmember' element={<Layout pages={<EditMember/>} /> }/>
         {/* Employee */}

         {/* Admin */}
         <Route path='/admin' element={<Layout pages={<Admin/>} /> }/>
         <Route path='/addAdmin' element={<Layout pages={<AddAdmin/>} /> }/>
         {/* Admin */}

    </Routes>
    </BrowserRouter>
  )
}
